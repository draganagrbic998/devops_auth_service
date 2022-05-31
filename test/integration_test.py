from auth_service.main import JWT_SECRET, JWT_ALGORITHM, get_password_hash, pwd_context
from sqlalchemy import create_engine
from kafka import KafkaProducer, KafkaConsumer

import pytest
import requests
import time
import json
import jwt

db = create_engine('postgresql://postgres:postgres@localhost:5433/postgres')
kafka_producer = None
AUTH_URL = 'http://localhost:8000/auth'

@pytest.fixture(scope='session', autouse=True)
def do_something(request):
    time.sleep(30)
    global kafka_producer
    kafka_producer = KafkaProducer(bootstrap_servers='localhost:29092', value_serializer=lambda v: json.dumps(v).encode('utf-8'))


def test_registration_missing_first_name():
    data = {
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'first_name'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_first_name():
    data = {
        'first_name': None,
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'first_name'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_first_name():
    data = {
        'first_name': '',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'first_name'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

def test_registration_missing_last_name():
    data = {
        'first_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'last_name'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_last_name():
    data = {
        'first_name': 'asd',
        'last_name': None,
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'last_name'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_last_name():
    data = {
        'first_name': 'asd',
        'last_name': '',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'last_name'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

def test_registration_missing_email():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'email'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_email():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': None,
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'email'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_email():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': '',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'email'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

def test_registration_missing_phone_number():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'phone_number'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_phone_number():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': None,
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'phone_number'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_phone_number():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': '',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'phone_number'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

def test_registration_missing_sex():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'sex'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_sex():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': None,
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'sex'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_sex():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': '',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'sex'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

def test_registration_missing_birth_date():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'birth_date'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_birth_date():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': None,
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'birth_date'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_birth_date():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'birth_date'
    assert body['detail'][0]['msg'] == 'invalid date format'
    assert body['detail'][0]['type'] == 'value_error.date'

def test_registration_missing_username():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'username'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_username():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': None,
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'username'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_username():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': '',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'username'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

def test_registration_missing_biography():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'biography'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_biography():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': None,
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'biography'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_biography():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': '',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'biography'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

def test_registration_missing_private():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'private'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_private():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': None,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'private'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_private():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': '',
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'private'
    assert body['detail'][0]['msg'] == 'value could not be parsed to a boolean'
    assert body['detail'][0]['type'] == 'type_error.bool'

def test_registration_missing_password():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'password'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_registration_null_password():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': None
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'password'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_registration_empty_password():
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': ''
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'password'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

def reset_table(number_of_rows=0):
    db.execute('delete from users')
    for i in range(number_of_rows):
        db.execute('insert into users (username, password, first_name, last_name) values (%s, %s, %s, %s)', 
                            (f'username {i+1}', get_password_hash(f'password {i+1}'), f'first_name {i+1}', f'last_name {i+1}'))

def test_registration_valid():
    reset_table()
    kafka_consumer = KafkaConsumer('profiles', bootstrap_servers=['localhost:29092'])
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'asd',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 200
    body = json.loads(res.text)
    assert body is None
    users = list(db.execute('select * from users'))
    assert len(users) == 1
    assert users[0]['username'] == 'asd'
    assert pwd_context.verify('asd', users[0]['password'])
    assert users[0]['first_name'] == 'asd'
    assert users[0]['last_name'] == 'asd'
    assert kafka_consumer.poll(update_offsets=False) is not None

def test_registration_taken_username():
    reset_table(1)
    data = {
        'first_name': 'asd',
        'last_name': 'asd',
        'email': 'asd',
        'phone_number': 'asd',
        'sex': 'asd',
        'birth_date': '2012-12-12',
        'username': 'username 1',
        'biography': 'asd',
        'private': False,
        'password': 'asd'
    }
    res = requests.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 400
    body = json.loads(res.text)
    assert body['detail'] == 'Username already exists'
