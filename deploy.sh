#!/bin/bash

# Build React frontend
cd frontend/website
npm install && npm start

# Start Flask backend
cd ../../backend
pip install -r requirements.txt
python app.py
