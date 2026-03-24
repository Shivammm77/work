# auth logic : authenticate , token creation , get current_user
from sqlalchemy.orm import Session
from database.Model.user import User
from fastapi import HTTPException , status , Depends
from datetime import timedelta , datetime
from fastapi.security import OAuth2PasswordBearer 
from database.Schema.schema import user 
from database.Model.user import User
from passlib.context import CryptContext
from jose import jwt , JWTError
from fastapi_mail import FastMail , MessageSchema , ConnectionConfig , MessageType
alg = "HS256"
Secret_Key = "Shivam"
bcrypt = CryptContext(schemes=['bcrypt'] , deprecated = ['auto'])
oauth2 = OAuth2PasswordBearer(tokenUrl="/v1/api/auth/login")
config = ConnectionConfig(
    MAIL_USERNAME = "sonishivam12356@gmail.com",
    MAIL_PASSWORD = "hwbekqutpunqxrch",
    MAIL_FROM = "sonishivam12356@gmail.com",
    MAIL_PORT = 587,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True
)
async def send_welcome_email(email: str, username: str):
    html = f"""
   hey {username} Welcome to the community 
    """
    
    message = MessageSchema(
        subject="Welcome to Our Community!",
        recipients=[email],
        body=html,
        subtype=MessageType.html
    )

    fm = FastMail(config)
    await fm.send_message(message)
def authenticate_user(username : str , password:str , db:Session):
    current_user = db.query(User).filter(User.username == username).first()
    
    if not current_user  or not bcrypt.verify( password, current_user.password ):
        raise HTTPException(status_code=400 , detail="user not found")
    return current_user
def create_token(user_id:int , username  , exp : timedelta):
    encode = {"id" : user_id , "sub" : username}
    expire = datetime.now() + exp
    encode.update({'exp':expire})
    return jwt.encode(encode , Secret_Key , algorithm=alg)


def create_user(user_data: user, db: Session):
    try:
        # Explicitly convert to string to avoid bcrypt type-mismatch errors
        plain_password = str(user_data.password)
        hashed_password = bcrypt.hash(plain_password)

        new_user = User(
            username=user_data.name,
            email=user_data.email,
            password=hashed_password,
            # Ensure 'create_at' exists in your SQLAlchemy Model
            # If the model uses 'created_at', change it here!
            create_at=user_data.created_at 
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user

    except Exception as e:
        db.rollback() # VERY IMPORTANT: Resets the connection for the next request
        print(f"DATABASE ERROR: {str(e)}") 
        raise HTTPException(status_code=500, detail=f"Creation failed: {str(e)}")
    
def getcurrentuser(token  : Session = Depends(oauth2)):
    
    try : 
        payload  = jwt.decode(token , Secret_Key , algorithms=[alg])
        if payload is None:
            raise HTTPException(status_code=403 , detail="invalid token ")
            
        user_id = payload.get("id")
        username = payload.get("sub")
        
        return {
            "user_id" : user_id,
            "username" : username,
            
        }
    except JWTError as e :
        raise HTTPException(status_code=400 , detail="invalid token") 

    

    


