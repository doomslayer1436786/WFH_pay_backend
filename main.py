from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, timedelta
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt

import os
# ... other imports

# --- CONFIGURATION & SECURITY ---
# Update this line:
MONGO_DETAILS = "mongodb+srv://kaiftokare19:Kaif%40786@wfhcafe-development.8zgicnw.mongodb.net/?appName=WFHCafe-Development" 
SECRET_KEY = "supersecretkey"
# --- CONFIGURATION & SECURITY ---
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Auth Helpers
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()
client = AsyncIOMotorClient(MONGO_DETAILS)
db = client.food_ordering_db
restaurant_collection = db.get_collection("restaurants")
user_collection = db.get_collection("users")

# --- DATA MODELS ---
class UpdateItemRequest(BaseModel):
    new_name: Optional[str] = None
    new_price: Optional[float] = None

# 1. User Models
class UserSignup(BaseModel):
    username: str
    password: str

class UserInDB(BaseModel):
    username: str
    hashed_password: str
    
class BillItem(BaseModel):
    name: str
    quantity: int
    price: float

class SaveBillRequest(BaseModel):
    restaurant_id: str
    items: List[BillItem]
    subtotal: float
    tax_amount: float
    service_amount: float
    discount_amount: float
    grand_total: float
    payment_method: str = "UPI"
    customer_note: Optional[str] = None

# 2. Restaurant Models
class MenuItem(BaseModel):
    name: str
    price: float

class BulkAddRequest(BaseModel):
    restaurant_id: str
    items: List[MenuItem]

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
@app.put("/restaurants/{restaurant_id}/items/{original_name}")
async def update_menu_item(
    restaurant_id: str, 
    original_name: str, 
    update_data: UpdateItemRequest,
):
    """
    Updates a specific item in the menu array.
    """
    # 1. Verify Ownership (Optional but recommended)
    # check_ownership(restaurant_id, current_user)

    # 2. Build the update query
    # We use "dot notation" with the positional operator $ 
    # 'menu.$.price' means "update the price of the matched item in the array"
    
    set_fields = {"last_updated": datetime.utcnow()}
    
    if update_data.new_price is not None:
        set_fields["menu.$.price"] = update_data.new_price
        
    if update_data.new_name is not None:
        set_fields["menu.$.name"] = update_data.new_name

    # 3. Perform Update
    result = await restaurant_collection.update_one(
        {
            "restaurant_id": restaurant_id,
            "menu.name": original_name  # <--- FIND the specific item
        },
        {
            "$set": set_fields
        }
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Item not found or no changes made")

    return {"status": "success", "message": f"Updated {original_name}"}
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    This function is the GATEKEEPER.
    It takes the token from the request, decodes it, finds the user in DB, 
    and returns the user object. If anything fails, it throws 401.
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
    # Check if user already exists
    existing_user = await user_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    # Hash password and save
    hashed_pwd = get_password_hash(user.password)
    new_user = {"username": user.username, "hashed_password": hashed_pwd}
    await user_collection.insert_one(new_user)
    
    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: UserSignup):
    # Find user
    db_user = await user_collection.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    # Generate Token
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- PROTECTED RESTAURANT ROUTES ---

@app.post("/restaurants/bulk-add-items")
async def bulk_add_items(
    payload: BulkAddRequest, 
    current_user: dict = Depends(get_current_user) # <--- THIS PROTECTS THE ROUTE
):
    now = datetime.utcnow()
    rid = payload.restaurant_id
    user_id = str(current_user["_id"]) # The ID of the logged-in user

    # 1. CHECK OWNERSHIP
    # We check if the restaurant exists.
    existing_restaurant = await restaurant_collection.find_one({"restaurant_id": rid})

    if existing_restaurant:
        # If it exists, we MUST check if the 'owner_id' matches the current user
        if existing_restaurant.get("owner_id") != user_id:
            raise HTTPException(
                status_code=403, 
                detail="You do not own this restaurant. Access forbidden."
            )
    
    # 2. PREPARE DATA
    new_items = [item.model_dump() for item in payload.items]

    # 3. UPSERT WITH OWNER ID
    # If we are creating a NEW restaurant, we set 'owner_id' to the current user
    update_query = {
        "$addToSet": {"menu": { "$each": new_items }},
        "$set": {"last_updated": now},
        "$setOnInsert": {
            "restaurant_id": rid,
            "isActive": True,
            "created_at": now,
            "owner_id": user_id  # <--- Bind the restaurant to this user
        }
    }

    result = await restaurant_collection.update_one(
        {"restaurant_id": rid},
        update_query,
        upsert=True
    )

    return {
        "status": "success", 
        "owner": current_user["username"],
        "items_added": len(new_items)
    }

@app.get("/restaurants/{restaurant_id}/menu")
async def get_menu(
    restaurant_id: str, 
    current_user: dict = Depends(get_current_user) # <--- PROTECTS READ ACCESS TOO
):
    restaurant = await restaurant_collection.find_one({"restaurant_id": restaurant_id})
    
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found")
        
    # OPTIONAL: Uncomment this if you want ONLY the owner to see the menu
    # if restaurant.get("owner_id") != str(current_user["_id"]):
    #     raise HTTPException(status_code=403, detail="Not authorized to view this menu")

    return {
        "restaurant_id": restaurant_id,
        "menu": restaurant.get("menu", [])
    }

@app.post("/restaurants/save-bill")
async def save_bill(bill: SaveBillRequest, current_user: dict = Depends(get_current_user)):
    """
    Saves a completed bill to the database.
    """
    bill_data = bill.model_dump()
    bill_data["created_at"] = datetime.utcnow()
    bill_data["owner_id"] = str(current_user["_id"])
    
    # Store in a new collection 'bills'
    new_bill = await db.get_collection("bills").insert_one(bill_data)
    
    return {
        "status": "success", 
        "bill_id": str(new_bill.inserted_id),
        "message": "Bill saved to history"
    }
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)