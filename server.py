from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Query, Depends
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os
import logging
import bcrypt
import jwt
import cloudinary
import cloudinary.utils
import cloudinary.uploader
import time
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Cloudinary configuration
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "fallback-secret-key")
JWT_ALGORITHM = "HS256"

# Create the main app
app = FastAPI(title="Grocery Shop Admin API")

# Create routers
api_router = APIRouter(prefix="/api")
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
products_router = APIRouter(prefix="/products", tags=["Products"])
orders_router = APIRouter(prefix="/orders", tags=["Orders"])
cloudinary_router = APIRouter(prefix="/cloudinary", tags=["Cloudinary"])

# ===================== PYDANTIC MODELS =====================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str

class ProductCreate(BaseModel):
    name: str
    price: float
    category: str
    description: Optional[str] = ""
    stock: Optional[int] = 0
    image_url: Optional[str] = ""
    image_public_id: Optional[str] = ""

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    description: Optional[str] = None
    stock: Optional[int] = None
    image_url: Optional[str] = None
    image_public_id: Optional[str] = None

class ProductResponse(BaseModel):
    id: str
    name: str
    price: float
    category: str
    description: str
    stock: int
    image_url: str
    image_public_id: str
    created_at: str
    updated_at: str

class OrderItem(BaseModel):
    product_id: str
    product_name: str
    quantity: int
    price: float

class OrderCreate(BaseModel):
    customer_name: Optional[str] = ""
    phone: str
    address: Optional[str] = ""
    items: List[OrderItem]
    total_price: float

class OrderStatusUpdate(BaseModel):
    status: str  # Pending, Confirmed, Delivered

class OrderResponse(BaseModel):
    id: str
    customer_name: str
    phone: str
    address: str
    items: List[dict]
    total_price: float
    status: str
    created_at: str
    updated_at: str

# ===================== HELPER FUNCTIONS =====================

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "type": "access"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "refresh"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return {
            "id": str(user["_id"]),
            "email": user["email"],
            "name": user["name"],
            "role": user["role"]
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ===================== AUTH ROUTES =====================

@auth_router.post("/login")
async def login(request: LoginRequest, response: Response):
    email = request.email.lower()
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    user_id = str(user["_id"])
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=86400, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="lax", max_age=604800, path="/")
    
    return {
        "id": user_id,
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "access_token": access_token
    }

@auth_router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out successfully"}

@auth_router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@auth_router.post("/refresh")
async def refresh_token(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        user_id = str(user["_id"])
        access_token = create_access_token(user_id, user["email"])
        response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=86400, path="/")
        
        return {"message": "Token refreshed"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

# ===================== PRODUCTS ROUTES =====================

@products_router.get("")
async def get_products(
    search: Optional[str] = None,
    category: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
):
    query = {}
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]
    if category and category != "all":
        query["category"] = category
    
    products = await db.products.find(query, {"_id": 1, "name": 1, "price": 1, "category": 1, "description": 1, "stock": 1, "image_url": 1, "image_public_id": 1, "created_at": 1, "updated_at": 1}).skip(skip).limit(limit).to_list(limit)
    
    result = []
    for p in products:
        result.append({
            "id": str(p["_id"]),
            "name": p.get("name", ""),
            "price": p.get("price", 0),
            "category": p.get("category", ""),
            "description": p.get("description", ""),
            "stock": p.get("stock", 0),
            "image_url": p.get("image_url", ""),
            "image_public_id": p.get("image_public_id", ""),
            "created_at": p.get("created_at", ""),
            "updated_at": p.get("updated_at", "")
        })
    return result

@products_router.get("/categories")
async def get_categories():
    categories = await db.products.distinct("category")
    return categories

@products_router.get("/{product_id}")
async def get_product(product_id: str):
    try:
        product = await db.products.find_one({"_id": ObjectId(product_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid product ID")
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return {
        "id": str(product["_id"]),
        "name": product.get("name", ""),
        "price": product.get("price", 0),
        "category": product.get("category", ""),
        "description": product.get("description", ""),
        "stock": product.get("stock", 0),
        "image_url": product.get("image_url", ""),
        "image_public_id": product.get("image_public_id", ""),
        "created_at": product.get("created_at", ""),
        "updated_at": product.get("updated_at", "")
    }

@products_router.post("")
async def create_product(product: ProductCreate, current_user: dict = Depends(get_current_user)):
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "name": product.name,
        "price": product.price,
        "category": product.category,
        "description": product.description or "",
        "stock": product.stock or 0,
        "image_url": product.image_url or "",
        "image_public_id": product.image_public_id or "",
        "created_at": now,
        "updated_at": now
    }
    result = await db.products.insert_one(doc)
    return {
        "id": str(result.inserted_id),
        "name": doc["name"],
        "price": doc["price"],
        "category": doc["category"],
        "description": doc["description"],
        "stock": doc["stock"],
        "image_url": doc["image_url"],
        "image_public_id": doc["image_public_id"],
        "created_at": doc["created_at"],
        "updated_at": doc["updated_at"]
    }

@products_router.put("/{product_id}")
async def update_product(product_id: str, product: ProductUpdate, current_user: dict = Depends(get_current_user)):
    try:
        existing = await db.products.find_one({"_id": ObjectId(product_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid product ID")
    if not existing:
        raise HTTPException(status_code=404, detail="Product not found")
    
    update_data = {}
    if product.name is not None:
        update_data["name"] = product.name
    if product.price is not None:
        update_data["price"] = product.price
    if product.category is not None:
        update_data["category"] = product.category
    if product.description is not None:
        update_data["description"] = product.description
    if product.stock is not None:
        update_data["stock"] = product.stock
    if product.image_url is not None:
        update_data["image_url"] = product.image_url
    if product.image_public_id is not None:
        update_data["image_public_id"] = product.image_public_id
    
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.products.update_one({"_id": ObjectId(product_id)}, {"$set": update_data})
    
    updated = await db.products.find_one({"_id": ObjectId(product_id)})
    return {
        "id": str(updated["_id"]),
        "name": updated.get("name", ""),
        "price": updated.get("price", 0),
        "category": updated.get("category", ""),
        "description": updated.get("description", ""),
        "stock": updated.get("stock", 0),
        "image_url": updated.get("image_url", ""),
        "image_public_id": updated.get("image_public_id", ""),
        "created_at": updated.get("created_at", ""),
        "updated_at": updated.get("updated_at", "")
    }

@products_router.delete("/{product_id}")
async def delete_product(product_id: str, current_user: dict = Depends(get_current_user)):
    try:
        product = await db.products.find_one({"_id": ObjectId(product_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid product ID")
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Delete image from Cloudinary if exists
    if product.get("image_public_id"):
        try:
            cloudinary.uploader.destroy(product["image_public_id"], invalidate=True)
        except Exception as e:
            logger.error(f"Failed to delete image from Cloudinary: {e}")
    
    await db.products.delete_one({"_id": ObjectId(product_id)})
    return {"message": "Product deleted successfully"}

# ===================== ORDERS ROUTES =====================

@orders_router.get("")
async def get_orders(
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
):
    query = {}
    if status and status != "all":
        query["status"] = status
    
    orders = await db.orders.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    result = []
    for o in orders:
        result.append({
            "id": str(o["_id"]),
            "customer_name": o.get("customer_name", ""),
            "phone": o.get("phone", ""),
            "address": o.get("address", ""),
            "items": o.get("items", []),
            "total_price": o.get("total_price", 0),
            "status": o.get("status", "Pending"),
            "created_at": o.get("created_at", ""),
            "updated_at": o.get("updated_at", "")
        })
    return result

@orders_router.get("/count")
async def get_orders_count():
    """Get count of new orders since last check (for polling)"""
    # Get orders from last 30 seconds
    thirty_seconds_ago = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    count = await db.orders.count_documents({"created_at": {"$gte": thirty_seconds_ago}})
    return {"new_orders": count}

@orders_router.get("/{order_id}")
async def get_order(order_id: str):
    try:
        order = await db.orders.find_one({"_id": ObjectId(order_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid order ID")
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return {
        "id": str(order["_id"]),
        "customer_name": order.get("customer_name", ""),
        "phone": order.get("phone", ""),
        "address": order.get("address", ""),
        "items": order.get("items", []),
        "total_price": order.get("total_price", 0),
        "status": order.get("status", "Pending"),
        "created_at": order.get("created_at", ""),
        "updated_at": order.get("updated_at", "")
    }

@orders_router.post("")
async def create_order(order: OrderCreate):
    """Public endpoint for creating orders (will be used by Android app)"""
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "customer_name": order.customer_name or "",
        "phone": order.phone,
        "address": order.address or "",
        "items": [item.model_dump() for item in order.items],
        "total_price": order.total_price,
        "status": "Pending",
        "created_at": now,
        "updated_at": now
    }
    result = await db.orders.insert_one(doc)
    return {
        "id": str(result.inserted_id),
        "customer_name": doc["customer_name"],
        "phone": doc["phone"],
        "address": doc["address"],
        "items": doc["items"],
        "total_price": doc["total_price"],
        "status": doc["status"],
        "created_at": doc["created_at"],
        "updated_at": doc["updated_at"]
    }

@orders_router.put("/{order_id}/status")
async def update_order_status(order_id: str, status_update: OrderStatusUpdate, current_user: dict = Depends(get_current_user)):
    if status_update.status not in ["Pending", "Confirmed", "Delivered"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be Pending, Confirmed, or Delivered")
    
    try:
        existing = await db.orders.find_one({"_id": ObjectId(order_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid order ID")
    if not existing:
        raise HTTPException(status_code=404, detail="Order not found")
    
    await db.orders.update_one(
        {"_id": ObjectId(order_id)},
        {"$set": {"status": status_update.status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    updated = await db.orders.find_one({"_id": ObjectId(order_id)})
    return {
        "id": str(updated["_id"]),
        "customer_name": updated.get("customer_name", ""),
        "phone": updated.get("phone", ""),
        "address": updated.get("address", ""),
        "items": updated.get("items", []),
        "total_price": updated.get("total_price", 0),
        "status": updated.get("status", "Pending"),
        "created_at": updated.get("created_at", ""),
        "updated_at": updated.get("updated_at", "")
    }

# ===================== CLOUDINARY ROUTES =====================

@cloudinary_router.get("/signature")
async def generate_cloudinary_signature(
    resource_type: str = Query("image", enum=["image", "video"]),
    folder: str = "grocery-products",
    current_user: dict = Depends(get_current_user)
):
    timestamp = int(time.time())
    params = {
        "timestamp": timestamp,
        "folder": folder,
        "resource_type": resource_type
    }
    
    signature = cloudinary.utils.api_sign_request(
        params,
        os.getenv("CLOUDINARY_API_SECRET")
    )
    
    return {
        "signature": signature,
        "timestamp": timestamp,
        "cloud_name": os.getenv("CLOUDINARY_CLOUD_NAME"),
        "api_key": os.getenv("CLOUDINARY_API_KEY"),
        "folder": folder,
        "resource_type": resource_type
    }

@cloudinary_router.delete("/image/{public_id:path}")
async def delete_cloudinary_image(public_id: str, current_user: dict = Depends(get_current_user)):
    try:
        result = cloudinary.uploader.destroy(public_id, invalidate=True)
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ===================== DASHBOARD ROUTES =====================

@api_router.get("/dashboard/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    total_products = await db.products.count_documents({})
    total_orders = await db.orders.count_documents({})
    pending_orders = await db.orders.count_documents({"status": "Pending"})
    confirmed_orders = await db.orders.count_documents({"status": "Confirmed"})
    delivered_orders = await db.orders.count_documents({"status": "Delivered"})
    
    # Get recent orders
    recent_orders = await db.orders.find().sort("created_at", -1).limit(5).to_list(5)
    recent = []
    for o in recent_orders:
        recent.append({
            "id": str(o["_id"]),
            "customer_name": o.get("customer_name", ""),
            "phone": o.get("phone", ""),
            "address": o.get("address", ""),
            "total_price": o.get("total_price", 0),
            "status": o.get("status", "Pending"),
            "created_at": o.get("created_at", "")
        })
    
    return {
        "total_products": total_products,
        "total_orders": total_orders,
        "pending_orders": pending_orders,
        "confirmed_orders": confirmed_orders,
        "delivered_orders": delivered_orders,
        "recent_orders": recent
    }

# ===================== ROOT ROUTE =====================

@api_router.get("/")
async def root():
    return {"message": "Grocery Shop Admin API", "version": "1.0.0"}

# ===================== INCLUDE ROUTERS =====================

api_router.include_router(auth_router)
api_router.include_router(products_router)
api_router.include_router(orders_router)
api_router.include_router(cloudinary_router)
app.include_router(api_router)

# ===================== CORS MIDDLEWARE =====================

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[os.environ.get('FRONTEND_URL', 'http://localhost:3000'), "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===================== STARTUP EVENT =====================

@app.on_event("startup")
async def startup_event():
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.products.create_index("name")
    await db.products.create_index("category")
    await db.orders.create_index("status")
    await db.orders.create_index("created_at")
    
    # Seed admin user
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@grocery.com").lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@123")
    
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        hashed = hash_password(admin_password)
        await db.users.insert_one({
            "email": admin_email,
            "password_hash": hashed,
            "name": "Admin",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        logger.info(f"Admin user created: {admin_email}")
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one(
            {"email": admin_email},
            {"$set": {"password_hash": hash_password(admin_password)}}
        )
        logger.info(f"Admin password updated for: {admin_email}")
    
    logger.info("Grocery Shop Admin API started successfully")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
