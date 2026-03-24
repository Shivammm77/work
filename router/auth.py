# Login ,Signup
# login - check user authenticated  , then access token
# sign up : create user
from fastapi import APIRouter  , Depends , HTTPException , BackgroundTasks
from database.db import get_db
from sqlalchemy.orm import Session 
from database.Schema.schema import user
from database.Model import User
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from Service.authl3 import authenticate_user , create_token , create_user ,send_welcome_email

from fastapi import Request
from fastapi import status


auth  = APIRouter(prefix="/auth")    
@auth.post("/login")
def login(formdata :OAuth2PasswordRequestForm = Depends(), db: Session =Depends(get_db)):
    user = authenticate_user(formdata.username , formdata.password ,db)
    if not user :
        raise  HTTPException(status_code=401 , detail="user not found")
    token = create_token(user.user_id , user.username ,timedelta(minutes=30) )
    return {
        "access_token" : token,
        "token_type" : "bearer",
        
    }


@auth.post("/Signup")
def Signup(user_data: user, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 1. Check if user already exists BEFORE calling create_user
    # This prevents the database from crashing on a 'Unique Constraint' error
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # 2. Call the create_user function
    new_user = create_user(user_data, db)
    
    # 3. Add background task using the data from the newly created DB object
    # background_tasks.add_task(send_welcome_email, new_user.email, new_user.username)
    
    return new_user