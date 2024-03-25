#!/bin/bash

# Build React frontend
cd frontend
npm install && npm run build

# Start Flask backend
cd ../backend
python app.py
