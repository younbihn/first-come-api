from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

@app.get("/")
def root():
    return {"status": "alive"}

@app.get("/hello")
def hello(name: str = "익명"):
    return {"message": f"안녕하세요, {name}님"}

class Item(BaseModel):
    name: str
    price: int

@app.post("/items")
def create_item(item: Item):
    return {"created": item.name, "price": item.price}