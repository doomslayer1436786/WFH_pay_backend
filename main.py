import os
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- CONFIGURATION & SECURITY ---
# Get secrets from Environment Variables (Set these in Render Dashboard)
MONGO_DETAILS = "mongodb+srv://kaiftokare19:Kaif%40786@wfhcafe-development.8zgicnw.mongodb.net/?appName=WFHCafe-Development"
SECRET_KEY = "supersecretkey" # Fallback only for local testing
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Auth Helpers
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()

# --- CORS MIDDLEWARE (Fixes "Failed to fetch") ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (React, Mobile, etc.)
    allow_credentials=True,
    allow_methods=["*"],  # Allows GET, POST, PUT, DELETE, etc.
    allow_headers=["*"],
)

# --- DATABASE CONNECTION ---
client = AsyncIOMotorClient(MONGO_DETAILS)
db = client.food_ordering_db
restaurant_collection = db.get_collection("restaurants")
user_collection = db.get_collection("users")
bill_collection = db.get_collection("bills")

# --- DATA MODELS ---

# 1. User Models
class UserSignup(BaseModel):
    username: str
    password: str
    restaurant_name: str
    restaurant_id: str  # Unique ID chosen by user at signup

class UserLogin(BaseModel):
    username: str
    password: str

# 2. Restaurant Models
class MenuItem(BaseModel):
    name: str
    price: float

class UpdateItemRequest(BaseModel):
    new_name: Optional[str] = None
    new_price: Optional[float] = None

class BulkAddRequest(BaseModel):
    # No restaurant_id here (Server finds it automatically)
    items: List[MenuItem]

# 3. Bill Models
class BillItem(BaseModel):
    name: str
    quantity: int
    price: float

class SaveBillRequest(BaseModel):
    # No restaurant_id here
    items: List[BillItem]
    subtotal: float
    tax_amount: float
    service_amount: float
    discount_amount: float
    grand_total: float
    payment_method: str = "UPI"
    customer_note: Optional[str] = None

# --- SECURITY FUNCTIONS ---

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Decodes the token and retrieves the current user + their restaurant_id
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = await user_collection.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return user

# --- AUTH ROUTES ---

@app.post("/signup")
async def signup(user: UserSignup):
    # 1. Check if Username exists
    existing_user = await user_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    # 2. Check if Restaurant ID exists
    existing_restaurant = await restaurant_collection.find_one({"restaurant_id": user.restaurant_id})
    if existing_restaurant:
        raise HTTPException(status_code=400, detail="Restaurant ID already taken. Please choose another.")

    # 3. Create the User (and link the restaurant_id to them)
    hashed_pwd = get_password_hash(user.password)
    new_user = {
        "username": user.username, 
        "hashed_password": hashed_pwd,
        "restaurant_id": user.restaurant_id  # <--- LINKED FOREVER
    }
    insert_result = await user_collection.insert_one(new_user)
    user_db_id = insert_result.inserted_id

    # 4. Create the Empty Restaurant Menu
    new_restaurant = {
        "restaurant_id": user.restaurant_id,
        "name": user.restaurant_name,
        "owner_id": str(user_db_id),
        "menu": [],
        "created_at": datetime.utcnow(),
        "last_updated": datetime.utcnow()
    }
    await restaurant_collection.insert_one(new_restaurant)
    
    return {
        "message": "Account created successfully",
        "restaurant_id": user.restaurant_id
    }

@app.post("/login")
async def login(user: UserLogin):
    # Find user
    db_user = await user_collection.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    # Generate Token
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- SMART RESTAURANT ROUTES (Auto-detected ID) ---

@app.get("/my-menu")
async def get_my_menu(current_user: dict = Depends(get_current_user)):
    """
    Fetch the menu strictly for the logged-in user.
    """
    my_restaurant_id = current_user.get("restaurant_id")
    
    restaurant = await restaurant_collection.find_one({"restaurant_id": my_restaurant_id})
    
    if not restaurant:
        # Should not happen if signup worked, but just in case
        return {"menu": []}

    return {
        "restaurant_name": restaurant.get("name"),
        "restaurant_id": my_restaurant_id,
        "menu": restaurant.get("menu", [])
    }

@app.post("/my-menu/add")
async def add_menu_items(
    payload: BulkAddRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Adds items to the logged-in user's menu.
    """
    my_restaurant_id = current_user.get("restaurant_id")
    
    # Prepare data
    new_items = [item.model_dump() for item in payload.items]

    # Update DB
    result = await restaurant_collection.update_one(
        {"restaurant_id": my_restaurant_id}, 
        {
            "$push": {"menu": {"$each": new_items}},
            "$set": {"last_updated": datetime.utcnow()}
        }
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Restaurant not found")

    return {
        "status": "success", 
        "restaurant_id": my_restaurant_id,
        "items_added": len(new_items)
    }

@app.put("/my-menu/items/{original_name}")
async def update_menu_item(
    original_name: str, 
    update_data: UpdateItemRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Updates a specific item in the user's menu.
    """
    my_restaurant_id = current_user.get("restaurant_id")
    
    set_fields = {"last_updated": datetime.utcnow()}
    
    if update_data.new_price is not None:
        set_fields["menu.$.price"] = update_data.new_price
        
    if update_data.new_name is not None:
        set_fields["menu.$.name"] = update_data.new_name

    result = await restaurant_collection.update_one(
        {
            "restaurant_id": my_restaurant_id,
            "menu.name": original_name
        },
        {
            "$set": set_fields
        }
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")

    return {"status": "success", "message": f"Updated {original_name}"}

@app.post("/bills/save")
async def save_bill(bill: SaveBillRequest, current_user: dict = Depends(get_current_user)):
    """
    Saves a bill and tags it with the user's restaurant ID.
    """
    my_restaurant_id = current_user.get("restaurant_id")

    bill_data = bill.model_dump()
    bill_data["restaurant_id"] = my_restaurant_id
    bill_data["owner_id"] = str(current_user["_id"])
    bill_data["created_at"] = datetime.utcnow()
    
    new_bill = await bill_collection.insert_one(bill_data)
    
    return {
        "status": "success", 
        "bill_id": str(new_bill.inserted_id)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
