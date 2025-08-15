#!/usr/bin/env python3
"""
NVD API Dashboard - Simple Startup Script
Created by Abhinav U

Just starts backend and frontend together.
"""

import subprocess
import sys
import os
import time

def start_backend():
    """Start the FastAPI backend with uvicorn"""
    print("🚀 Starting backend (FastAPI)...")
    backend_cmd = [
        sys.executable, "-m", "uvicorn", 
        "app.main:app", 
        "--host", "0.0.0.0", 
        "--port", "8000", 
        "--reload"
    ]
    return subprocess.Popen(backend_cmd, cwd=os.getcwd())

def start_frontend():
    """Start the frontend server"""
    print("🚀 Starting frontend (Node.js)...")
    frontend_cmd = ["npm", "start"]
    return subprocess.Popen(frontend_cmd, cwd=os.path.join(os.getcwd(), "frontend"))

def main():
    print("========================================")
    print("   NVD API Dashboard - Starting Up")
    print("   Created by Abhinav U")  
    print("========================================")
    print()
    
    try:
        # Start backend
        backend_process = start_backend()
        time.sleep(2)
        
        # Start frontend  
        frontend_process = start_frontend()
        time.sleep(2)
        
        print()
        print("✅ Both services started!")
        print("📱 Frontend: http://localhost:3000")
        print("🔧 Backend:  http://localhost:8000")
        print("📚 API Docs: http://localhost:8000/docs")
        print()
        print("Press Ctrl+C to stop both services...")
        
        # Wait for processes
        try:
            backend_process.wait()
        except KeyboardInterrupt:
            print("\n🛑 Stopping services...")
            backend_process.terminate()
            frontend_process.terminate()
            print("✅ Services stopped")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
