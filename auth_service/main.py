from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi_contrib.conf import settings
from sqlalchemy import create_engine
from kafka import KafkaProducer, KafkaConsumer
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jaeger_client import Config
from opentracing.scope_managers.asyncio import AsyncioScopeManager
from prometheus_client import Counter
from prometheus_fastapi_instrumentator import Instrumentator, metrics
from prometheus_fastapi_instrumentator.metrics import Info

import uvicorn
import datetime
import time
import json
import jwt
import threading
import os

DB_USERNAME = os.getenv('DB_USERNAME', 'postgres')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'postgres')
DB_HOST = os.getenv('DB_HOST', 'auth_service_db')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'postgres')
KAFKA_HOST = os.getenv('KAFKA_HOST', 'kafka')
KAFKA_PORT = os.getenv('KAFKA_PORT', '9092')
KAFKA_EVENTS_TOPIC = os.getenv('KAFKA_EVENTS_TOPIC', 'events')
KAFKA_PROFILES_TOPIC = os.getenv('KAFKA_PROFILES_TOPIC', 'profiles')
KAFKA_AUTH_TOPIC = os.getenv('KAFKA_AUTH_TOPIC', 'auth')
JWT_SECRET = os.getenv('JWT_SECRET', 'jwt_secret')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
AGENT_APPLICATION_API_KEY = os.getenv('AGENT_APPLICATION_API_KEY', 'agent_application_api_key')
AUTH_URL = '/auth'

app = FastAPI(title='Auth Service API')
db = create_engine(f'postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')
kafka_producer = None
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:4200'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

def setup_opentracing(app):
    config = Config(
        config={
            "local_agent": {
                "reporting_host": settings.jaeger_host,
                "reporting_port": settings.jaeger_port
            },
            "sampler": {
                "type": settings.jaeger_sampler_type,
                "param": settings.jaeger_sampler_rate,
            },
            "trace_id_header": settings.trace_id_header
        },
        service_name="auth_service",
        validate=True,
        scope_manager=AsyncioScopeManager()
    )

    app.state.tracer = config.initialize_tracer()
    app.tracer = app.state.tracer

setup_opentracing(app)

def http_404_requests():
    METRIC = Counter(
        "http_404_requests",
        "Number of times a 404 request has occured.",
        labelnames=("path",)
    )

    def instrumentation(info: Info):
        if info.response.status_code == 404:
            METRIC.labels(info.request.url).inc()

    return instrumentation

def http_unique_users():
    METRIC = Counter(
        "http_unique_users",
        "Number of unique http users.",
        labelnames=("user",)
    )

    def instrumentation(info: Info):
        try:
            user = f'{info.request.client.host} {info.request.headers["User-Agent"]}'
        except:
            user = f'{info.request.client.host} Unknown'
        METRIC.labels(user).inc()

    return instrumentation


instrumentator = Instrumentator(excluded_handlers=["/metrics"])
instrumentator.add(metrics.default())
instrumentator.add(metrics.combined_size())
instrumentator.add(http_404_requests())
instrumentator.add(http_unique_users())
instrumentator.instrument(app).expose(app)

class Registration(BaseModel):
    first_name: str = Field(description='First Name', min_length=1)
    last_name: str = Field(description='Last Name', min_length=1)
    email: str = Field(description='Email', min_length=1)
    phone_number: str = Field(description='Phone Number', min_length=1)
    sex: str = Field(description='Sex', min_length=1)
    birth_date: datetime.date = Field(description='Birth Date')
    username: str = Field(description='Username', min_length=1)
    biography: str = Field(description='Biography', min_length=1)
    private: bool = Field(description='Flag if profile is private')
    password: str = Field(description='Password', min_length=1)

class Login(BaseModel):
    username: str = Field(description='Username', min_length=1)
    password: str = Field(description='Password', min_length=1)

def get_password_hash(password: str):
    return pwd_context.hash(password)

def register_kafka_producer():
    global kafka_producer
    while True:
        try:
            kafka_producer = KafkaProducer(bootstrap_servers=f'{KAFKA_HOST}:{KAFKA_PORT}', value_serializer=lambda v: json.dumps(v).encode('utf-8'))
            break
        except:
            time.sleep(3)   

def register_auth_consumer():
    def poll():
        while True:
            try:
                consumer = KafkaConsumer(KAFKA_AUTH_TOPIC, bootstrap_servers=[f'{KAFKA_HOST}:{KAFKA_PORT}'])
                break
            except:
                time.sleep(3)

        for data in consumer:
            try:
                auth = json.loads(data.value.decode('utf-8'))
                db.execute('update users set username=%s, first_name=%s, last_name=%s where id=%s', (auth['username'], auth['first_name'], auth['last_name'], auth['id']))
            except:
                pass

    threading.Thread(target=poll).start()

def record_action(status: int, message: str, span):
    print("{0:10}{1}".format('ERROR:' if status >= 400 else 'INFO:', message))
    span.set_tag('http_status', status)
    span.set_tag('message', message)

def record_event(type: str, data: dict):
    kafka_producer.send(KAFKA_EVENTS_TOPIC, {
        'type': type,
        'data': data
    })

@app.post(f'{AUTH_URL}/registration')
def register(registration: Registration):
    with app.tracer.start_span('Registration Request') as span:
        try:
            span.set_tag('http_method', 'POST')
            try:
                db.execute('insert into users (username, password, first_name, last_name) values (%s, %s, %s, %s)', 
                    (registration.username, get_password_hash(registration.password), registration.first_name, registration.last_name))
            except:
                record_action(400, 'Request failed - Username already exists', span)
                raise HTTPException(status_code=400, detail='Username already exists')

            profile = dict(registration)
            profile['id'] = list(db.execute('select * from users where username=%s', (registration.username,)))[0]['id']
            profile['birth_date'] = profile['birth_date'].isoformat()
            del profile['password']
            kafka_producer.send(KAFKA_PROFILES_TOPIC, profile)

            record_action(200, 'Request successful', span)
            record_event('Profile Registration', profile)
        except Exception as e:
            record_action(500, 'Request failed', span)
            raise e




def run_service():
    register_kafka_producer()
    register_auth_consumer()
    uvicorn.run(app, host='0.0.0.0', port=8000)


if __name__ == '__main__':
    run_service()
