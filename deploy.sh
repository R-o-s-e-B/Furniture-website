#!/bin/bash

# Build React frontend
cd frontend/website
npm install && npm start

# Start Flask backend
cd ../../backend
python app.py
