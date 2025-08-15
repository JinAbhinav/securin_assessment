#!/usr/bin/env python3
"""
Quick runner script for the Ultimate CVE Assessment API Test Suite.

This script provides an easy way to run the comprehensive test suite with 
common configurations and automatically installs required dependencies.
"""

import subprocess
import sys
import os
from pathlib import Path

def ensure_dependencies():
    """Ensure required dependencies are installed."""
    required_packages = ['requests', 'pydantic']
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

def check_api_server():
    """Check if API server is running."""
    try:
        import requests
        response = requests.get('http://localhost:8000/health', timeout=5)
        return response.status_code == 200
    except:
        return False

def main():
    """Main runner function."""
    print("🚀 CVE Assessment API - Ultimate Test Suite Runner")
    print("=" * 60)
    
    # Ensure dependencies
    print("📦 Checking dependencies...")
    ensure_dependencies()
    
    # Check if API is running
    print("🔍 Checking API server...")
    if not check_api_server():
        print("❌ API server is not running at localhost:8000")
        print("   Please start the API server first:")
        print("   docker-compose up -d")
        sys.exit(1)
    
    print("✅ API server is running")
    
    # Run tests
    test_file = Path(__file__).parent / "test_api_endpoints_ultimate.py"
    
    print("\n🧪 Running Ultimate Test Suite...")
    print("   This may take a few minutes...")
    
    # Basic test run
    cmd = [sys.executable, str(test_file)]
    
    # Add flags based on user choice
    print("\nTest Options:")
    print("1. Basic tests only (fast)")
    print("2. Include performance/load tests")
    print("3. Include NVD API compliance tests")
    print("4. Full comprehensive test suite")
    
    try:
        choice = input("\nSelect option (1-4) [1]: ").strip() or "1"
    except KeyboardInterrupt:
        print("\n❌ Testing cancelled")
        sys.exit(1)
    
    if choice == "2":
        cmd.append("--include-load-tests")
    elif choice == "3":
        cmd.append("--include-nvd-tests")
    elif choice == "4":
        cmd.extend(["--include-load-tests", "--include-nvd-tests"])
    
    # Add output file
    output_file = f"test_results_{int(__import__('time').time())}.json"
    cmd.extend(["--output", output_file])
    
    print(f"\n🔧 Running command: {' '.join(cmd)}")
    print("=" * 60)
    
    # Execute tests
    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        
        if result.returncode == 0:
            print(f"\n🎉 All tests completed successfully!")
            print(f"📄 Detailed results saved to: {output_file}")
        else:
            print(f"\n⚠️  Some tests failed. Check the output above for details.")
            print(f"📄 Detailed results saved to: {output_file}")
        
        sys.exit(result.returncode)
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
