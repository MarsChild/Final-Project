from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
import sys
import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    f_name = Column(String(100), nullable=False)
    l_name = Column(String(100), nullable=False)
    email = Column(String(250), nullable=False)
    username = Column(String(250), nullable=False)
    password = Column(String, nullable=False)
    salt = Column(String(10), nullable=False)
    admin = Column(Boolean, nullable=False)