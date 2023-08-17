import uuid
import bcrypt
from db import DB
from sqlalchemy.orm.exc import DetachedInstanceError, NoResultFound


def _hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt)


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email, password):
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError("User {} already exists".format(user.email))
        except NoResultFound:
            hashed_pwd = _hash_password(password)
            user = self._db.add_user(email, hashed_pwd)
            return user

    def valid_login(self, email, password):
        try:
            user = self._db.find_user_by(email=email)
            if user:
                pwd_bytes = password.encode("utf-8")
                return bcrypt.checkpw(pwd_bytes, user.hashed_password)
        except NoResultFound:
            return False

    def _generate_uuid(self):
        return str(uuid.uuid4())

    def create_session(self, email):
        try:
            user = self._db.find_user_by(email=email)
            session_id = self._generate_uuid()
            user.session_id = session_id
            return session_id
        except NoResultFound:
            ...

    def get_user_from_session_id(self, session_id):
        if session_id:
            try:
                return self._db.find_user_by(session_id=session_id)
            except NoResultFound:
                ...

    def destroy_session(self, user_id):
        try:
            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            ...

    def get_reset_password_token(self, email):
        try:
            user = self._db.find_user_by(email=email)
            reset_token = self._generate_uuid()
            user.reset_token = reset_token
            return reset_token
        except NoResultFound:
            raise ValueError()

    def update_password(self, reset_token, password):
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            new_pwd = _hash_password(password)
            self._db.update_user(user.id, hashed_password=new_pwd, reset_token=None)
        except NoResultFound:
            raise ValueError()
