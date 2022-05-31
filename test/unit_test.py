from auth_service.main import app, AUTH_URL, JWT_SECRET, JWT_ALGORITHM, get_password_hash
from fastapi.testclient import TestClient
from mock import patch
import mock
import json
import jwt

class TestDB:
    def execute(self, sql, params):
        return []
    
class TestKP:
    def send(self, topic, data):
        pass
    
client = TestClient(app)
testDB = TestDB()
testKP = TestKP()

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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
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
    res = client.post(f'{AUTH_URL}/registration', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'password'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

@patch('auth_service.main.db', testDB)
@patch('auth_service.main.kafka_producer', testKP)
@patch('test.unit_test.testDB.execute', return_value=[{'id': 1}])
def test_registration_valid(param):
    with patch.object(testDB, 'execute', wraps=testDB.execute) as db_spy:
        with patch.object(testKP, 'send', wraps=testKP.send) as kafka_spy:
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
            res = client.post(f'{AUTH_URL}/registration', json=data)
            assert res.status_code == 200
            body = json.loads(res.text)
            assert body is None
            db_spy.assert_called()
            db_spy.assert_called_with('select * from users where username=%s', ('asd',))
            kafka_spy.assert_called()
            kafka_spy.assert_called_with('events', {
                'type': 'Profile Registration',
                'data': {
                    'id': 1,
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
            })

@patch('auth_service.main.db', testDB)
def test_registration_taken_username():
    with mock.patch('test.unit_test.testDB.execute') as db_mock:
        with patch.object(testDB, 'execute', wraps=testDB.execute) as db_spy:
            db_mock.side_effect = Exception()
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
            res = client.post(f'{AUTH_URL}/registration', json=data)
            assert res.status_code == 400
            body = json.loads(res.text)
            assert body['detail'] == 'Username already exists'
            db_spy.assert_called()


def test_login_missing_username():
    data = {
        'password': 'asd'
    }
    res = client.post(f'{AUTH_URL}/login', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'username'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_login_null_username():
    data = {
        'username': None,
        'password': 'asd'
    }
    res = client.post(f'{AUTH_URL}/login', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'username'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_login_empty_username():
    data = {
        'username': '',
        'password': 'asd'
    }
    res = client.post(f'{AUTH_URL}/login', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'username'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

def test_login_missing_password():
    data = {
        'username': 'asd'
    }
    res = client.post(f'{AUTH_URL}/login', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'password'
    assert body['detail'][0]['msg'] == 'field required'
    assert body['detail'][0]['type'] == 'value_error.missing'

def test_login_null_password():
    data = {
        'username': 'asd',
        'password': None
    }
    res = client.post(f'{AUTH_URL}/login', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'password'
    assert body['detail'][0]['msg'] == 'none is not an allowed value'
    assert body['detail'][0]['type'] == 'type_error.none.not_allowed'

def test_login_empty_password():
    data = {
        'username': 'asd',
        'password': ''
    }
    res = client.post(f'{AUTH_URL}/login', json=data)
    assert res.status_code == 422
    body = json.loads(res.text)
    assert body['detail'][0]['loc'][0] == 'body'
    assert body['detail'][0]['loc'][1] == 'password'
    assert body['detail'][0]['msg'] == 'ensure this value has at least 1 characters'
    assert body['detail'][0]['type'] == 'value_error.any_str.min_length'
    assert body['detail'][0]['ctx']['limit_value'] == 1

@patch('auth_service.main.db', testDB)
def test_login_invalid_username():
    with patch.object(testDB, 'execute', wraps=testDB.execute) as db_spy:
        data = {
            'username': 'asd',
            'password': 'asd'
        }
        res = client.post(f'{AUTH_URL}/login', json=data)
        assert res.status_code == 400
        body = json.loads(res.text)
        assert body['detail'] == 'User not found'
        db_spy.assert_called_once()
        db_spy.assert_called_with('select * from users where username=%s', ('asd',))

@patch('auth_service.main.db', testDB)
@patch('test.unit_test.testDB.execute', return_value=[{'password': get_password_hash('asd')}])
def test_login_invalid_password(param):
    with patch.object(testDB, 'execute', wraps=testDB.execute) as db_spy:
        data = {
            'username': 'asd',
            'password': 'qwe'
        }
        res = client.post(f'{AUTH_URL}/login', json=data)
        assert res.status_code == 400
        body = json.loads(res.text)
        assert body['detail'] == 'Bad password'
        db_spy.assert_called_once()
        db_spy.assert_called_with('select * from users where username=%s', ('asd',))

@patch('auth_service.main.db', testDB)
@patch('test.unit_test.testDB.execute', return_value=[{
    'id': 1,
    'username': 'asd', 
    'password': get_password_hash('asd'),
    'first_name': 'first_name 1',
    'last_name': 'last_name 1'
}])
def test_login_valid(param):
    with patch.object(testDB, 'execute', wraps=testDB.execute) as db_spy:
        data = {
            'username': 'asd',
            'password': 'asd'
        }
        res = client.post(f'{AUTH_URL}/login', json=data)
        assert res.status_code == 200
        body = json.loads(res.text)
        assert body['token'] == jwt.encode({
            'id': 1,
            'username': 'asd',
            'userFullName': 'first_name 1 last_name 1'
        }, JWT_SECRET, algorithm=JWT_ALGORITHM)
        db_spy.assert_called_once()
        db_spy.assert_called_with('select * from users where username=%s', ('asd',))

def test_auth_missing_token():
    res = client.get(AUTH_URL)
    assert res.status_code == 401
    body = json.loads(res.text)
    assert body['detail'] == 'Invalid token'
    
def test_auth_null_token():
    res = client.get(AUTH_URL, headers={'Authorization': None})
    assert res.status_code == 401
    body = json.loads(res.text)
    assert body['detail'] == 'Invalid token'

def test_auth_empty_token():
    res = client.get(AUTH_URL, headers={'Authorization': ''})
    assert res.status_code == 401
    body = json.loads(res.text)
    assert body['detail'] == 'Invalid token'

def test_auth_invalid_token():
    res = client.get(AUTH_URL, headers={'Authorization': 'asd'})
    assert res.status_code == 401
    body = json.loads(res.text)
    assert body['detail'] == 'Invalid token'

@patch('auth_service.main.db', testDB)
def test_auth_invalid_user():
    with patch.object(testDB, 'execute', wraps=testDB.execute) as db_spy:
        res = client.get(AUTH_URL, headers={'Authorization': jwt.encode({'username': 'asd'}, JWT_SECRET, algorithm=JWT_ALGORITHM)})
        assert res.status_code == 401
        body = json.loads(res.text)
        assert body['detail'] == 'User not found'
        db_spy.assert_called_once()
        db_spy.assert_called_with('select * from users where username=%s', ('asd',))

@patch('auth_service.main.db', testDB)
@patch('test.unit_test.testDB.execute', return_value=[{'username': 'asd'}])
def test_auth_valid(param):
    with patch.object(testDB, 'execute', wraps=testDB.execute) as db_spy:
        res = client.get(AUTH_URL, headers={'Authorization': jwt.encode({'username': 'asd'}, JWT_SECRET, algorithm=JWT_ALGORITHM)})
        assert res.status_code == 200
        body = json.loads(res.text)
        assert body is None
        db_spy.assert_called_once()
        db_spy.assert_called_with('select * from users where username=%s', ('asd',))
