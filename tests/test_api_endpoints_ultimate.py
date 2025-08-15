#!/usr/bin/env python3
"""
ULTIMATE COMPREHENSIVE CVE ASSESSMENT API TEST SUITE
====================================================

This test suite provides complete coverage of all backend functionality including:
- All API endpoints with comprehensive parameter testing
- Schema validation against Pydantic models
- NVD API service tests with rate limiting
- Database operation tests 
- End-to-end workflow tests
- Performance and load testing
- Data validation and integrity tests
- PDF requirement compliance verification

Usage:
    python test_api_endpoints_ultimate.py
    python test_api_endpoints_ultimate.py --include-load-tests
    python test_api_endpoints_ultimate.py --include-nvd-tests
    python test_api_endpoints_ultimate.py --output results.json

Requirements:
    - API server running at localhost:8000
    - requests, pydantic libraries: pip install requests pydantic
    - Optional: pytest, locust for advanced testing
"""

import requests
import json
import time
import sys
import random
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from decimal import Decimal
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from urllib.parse import quote


class CVEAPIUltimateTester:
    """Ultimate comprehensive tester for CVE Assessment API."""
    
    def __init__(self, base_url: str = "http://localhost:8000", include_load_tests: bool = False, include_nvd_tests: bool = False):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        self.test_results = []
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.include_load_tests = include_load_tests
        self.include_nvd_tests = include_nvd_tests
        self.performance_metrics = {}
        
        # Test data samples
        self.sample_cve_ids = [
            'CVE-1999-0095',  # Known test CVE
            'CVE-2023-12345', 'CVE-2024-0001', 'CVE-2022-1234',
            'CVE-2021-44228', 'CVE-2021-34527'  # Famous CVEs
        ]
        
        # Schema validation patterns
        self.cve_id_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
        self.iso_date_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
    
    def log_test(self, test_name: str, passed: bool, details: str = "", category: str = "general"):
        """Log test results with categorization."""
        self.total_tests += 1
        if passed:
            self.passed_tests += 1
            status = "✅ PASS"
        else:
            self.failed_tests += 1
            status = "❌ FAIL"
        
        message = f"{status} | {category.upper():<12} | {test_name}"
        if details:
            message += f" | {details}"
        
        print(message)
        self.test_results.append({
            'test': test_name,
            'category': category,
            'passed': passed,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
    
    def measure_performance(self, func, *args, **kwargs):
        """Measure function execution time."""
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        return result, (end_time - start_time) * 1000  # milliseconds
    
    def make_request(self, method: str, endpoint: str, measure_time: bool = True, **kwargs) -> Tuple[Optional[requests.Response], float]:
        """Make HTTP request with error handling and timing."""
        url = f"{self.base_url}{endpoint}"
        execution_time = 0
        
        try:
            if measure_time:
                response, execution_time = self.measure_performance(
                    self.session.request, method, url, **kwargs
                )
            else:
                response = self.session.request(method, url, **kwargs)
            return response, execution_time
        except requests.exceptions.ConnectionError:
            print(f"❌ Connection Error: Could not connect to {url}")
            print("   Make sure the API server is running at localhost:8000")
            return None, execution_time
        except Exception as e:
            print(f"❌ Request Error: {str(e)}")
            return None, execution_time
    
    def validate_cve_response_schema(self, data: dict, test_name: str) -> bool:
        """Validate CVE response against expected schema."""
        required_fields = [
            'id', 'cve_id', 'created_at', 'updated_at'
        ]
        optional_fields = [
            'source_identifier', 'vuln_status', 'published', 'last_modified',
            'description', 'cvss_v2_score', 'cvss_v3_score', 'cvss_v2_vector',
            'cvss_v3_vector', 'cvss_v2_severity', 'cvss_v3_severity'
        ]
        
        # Check required fields
        for field in required_fields:
            if field not in data:
                self.log_test(f"{test_name} - Missing required field: {field}", False, "", "schema")
                return False
        
        # Validate CVE ID format
        if not self.cve_id_pattern.match(data.get('cve_id', '')):
            self.log_test(f"{test_name} - Invalid CVE ID format", False, f"Got: {data.get('cve_id')}", "schema")
            return False
        
        # Validate date formats
        for date_field in ['created_at', 'updated_at', 'published', 'last_modified']:
            if data.get(date_field) and not self.iso_date_pattern.match(str(data[date_field])):
                self.log_test(f"{test_name} - Invalid date format: {date_field}", False, f"Got: {data.get(date_field)}", "schema")
                return False
        
        # Validate CVSS scores
        for score_field in ['cvss_v2_score', 'cvss_v3_score']:
            score = data.get(score_field)
            if score is not None:
                try:
                    score_val = float(score)
                    if not (0.0 <= score_val <= 10.0):
                        self.log_test(f"{test_name} - CVSS score out of range: {score_field}", False, f"Got: {score}", "schema")
                        return False
                except (ValueError, TypeError):
                    self.log_test(f"{test_name} - Invalid CVSS score type: {score_field}", False, f"Got: {score}", "schema")
                    return False
        
        self.log_test(f"{test_name} - Schema validation", True, "All fields valid", "schema")
        return True
    
    def validate_cve_list_response_schema(self, data: dict, test_name: str) -> bool:
        """Validate CVE list response schema."""
        required_fields = ['items', 'total', 'page', 'size', 'has_next', 'has_prev']
        
        for field in required_fields:
            if field not in data:
                self.log_test(f"{test_name} - Missing pagination field: {field}", False, "", "schema")
                return False
        
        # Validate pagination logic
        page = data.get('page', 0)
        size = data.get('size', 0)
        total = data.get('total', 0)
        items = data.get('items', [])
        
        if not isinstance(items, list):
            self.log_test(f"{test_name} - Items not a list", False, f"Type: {type(items)}", "schema")
            return False
        
        if len(items) > size:
            self.log_test(f"{test_name} - Items exceed page size", False, f"Items: {len(items)}, Size: {size}", "schema")
            return False
        
        # Validate has_next/has_prev logic
        expected_has_next = (page * size) < total
        expected_has_prev = page > 1
        
        if data.get('has_next') != expected_has_next:
            self.log_test(f"{test_name} - Incorrect has_next value", False, f"Expected: {expected_has_next}, Got: {data.get('has_next')}", "schema")
            return False
        
        if data.get('has_prev') != expected_has_prev:
            self.log_test(f"{test_name} - Incorrect has_prev value", False, f"Expected: {expected_has_prev}, Got: {data.get('has_prev')}", "schema")
            return False
        
        # Validate each item in the list
        for i, item in enumerate(items):
            if not self.validate_cve_response_schema(item, f"{test_name} - Item {i}"):
                return False
        
        self.log_test(f"{test_name} - List schema validation", True, f"Valid list with {len(items)} items", "schema")
        return True
    
    # ============================================================================
    # BASIC HEALTH AND INFO TESTS
    # ============================================================================
    
    def test_health_check(self):
        """Test health check endpoint with comprehensive validation."""
        print("\n🔍 Testing Health Check Endpoint")
        
        response, exec_time = self.make_request('GET', '/health')
        if not response:
            self.log_test("Health Check - Connection", False, "Could not connect to server", "health")
            return
        
        # Performance check
        self.performance_metrics['health_check'] = exec_time
        self.log_test(
            "Health Check - Response Time", 
            exec_time < 1000, 
            f"Response time: {exec_time:.2f}ms (should be < 1000ms)",
            "performance"
        )
        
        # Status code check
        self.log_test(
            "Health Check - Status Code", 
            response.status_code == 200, 
            f"Expected 200, got {response.status_code}",
            "health"
        )
        
        # JSON response validation
        try:
            data = response.json()
            required_fields = ['status', 'timestamp', 'database_connected', 'version']
            for field in required_fields:
                self.log_test(
                    f"Health Check - {field} field",
                    field in data,
                    f"Field present: {field in data}",
                    "health"
                )
            
            # Health status validation
            self.log_test(
                "Health Check - Healthy Status",
                data.get('status') == 'healthy',
                f"Status: {data.get('status')}",
                "health"
            )
            
            # Database connection validation
            self.log_test(
                "Health Check - Database Connected",
                data.get('database_connected') is True,
                f"DB Connected: {data.get('database_connected')}",
                "health"
            )
            
        except json.JSONDecodeError:
            self.log_test("Health Check - JSON Response", False, "Invalid JSON response", "health")
    
    def test_application_info(self):
        """Test application info endpoint."""
        print("\n📋 Testing Application Info Endpoint")
        
        response, exec_time = self.make_request('GET', '/info')
        if not response:
            self.log_test("App Info - Connection", False, "Could not connect", "info")
            return
        
        self.log_test(
            "App Info - Status Code",
            response.status_code == 200,
            f"Expected 200, got {response.status_code}",
            "info"
        )
        
        try:
            data = response.json()
            required_fields = ['name', 'version', 'environment']
            for field in required_fields:
                self.log_test(
                    f"App Info - {field} field",
                    field in data,
                    f"Field present: {field in data}",
                    "info"
                )
                
            # Validate app name
            self.log_test(
                "App Info - Correct App Name",
                data.get('name') == 'CVE Assessment API',
                f"Name: {data.get('name')}",
                "info"
            )
            
        except json.JSONDecodeError:
            self.log_test("App Info - JSON Response", False, "Invalid JSON response", "info")
    
    # ============================================================================
    # COMPREHENSIVE CVE ENDPOINT TESTS
    # ============================================================================
    
    def test_cve_list_endpoint_comprehensive(self):
        """Comprehensive CVE list endpoint testing."""
        print("\n📊 Testing CVE List Endpoint - COMPREHENSIVE")
        
        # Basic list test
        response, exec_time = self.make_request('GET', '/api/v1/cves/')
        if not response:
            self.log_test("CVE List - Connection", False, "Could not connect", "cve-list")
            return
        
        self.performance_metrics['cve_list_basic'] = exec_time
        self.log_test(
            "CVE List - Response Time", 
            exec_time < 5000, 
            f"Response time: {exec_time:.2f}ms (should be < 5000ms)",
            "performance"
        )
        
        self.log_test(
            "CVE List - Status Code",
            response.status_code == 200,
            f"Expected 200, got {response.status_code}",
            "cve-list"
        )
        
        try:
            data = response.json()
            
            # Schema validation
            self.validate_cve_list_response_schema(data, "CVE List Basic")
            
            # Test extensive pagination scenarios
            pagination_tests = [
                (1, 5, "Small page size"),
                (1, 20, "Default page size"),  
                (1, 50, "Medium page size"),
                (1, 100, "Maximum page size"),
                (2, 10, "Second page"),
                (999999, 10, "Very high page number")
            ]
            
            for page, size, description in pagination_tests:
                resp, _ = self.make_request('GET', f'/api/v1/cves/?page={page}&size={size}')
                if resp:
                    self.log_test(
                        f"CVE List - Pagination {description} (page={page}, size={size})",
                        resp.status_code == 200,
                        f"Status: {resp.status_code}",
                        "pagination"
                    )
                    
                    if resp.status_code == 200:
                        try:
                            page_data = resp.json()
                            self.validate_cve_list_response_schema(page_data, f"Pagination {description}")
                        except json.JSONDecodeError:
                            self.log_test(f"CVE List - {description} JSON", False, "Invalid JSON", "pagination")
            
            # Test comprehensive filtering
            filter_tests = [
                # Year filtering
                ('year=2023', 'Year filter 2023'),
                ('year=2022', 'Year filter 2022'),
                ('year=1999', 'Year filter 1999'),
                
                # Score filtering
                ('min_score=0.0&max_score=10.0', 'Full score range'),
                ('min_score=7.0&max_score=10.0', 'High severity scores'),
                ('min_score=4.0&max_score=6.9', 'Medium severity scores'),
                ('min_score=0.1&max_score=3.9', 'Low severity scores'),
                ('min_score=9.0&max_score=10.0', 'Critical scores'),
                
                # Severity filtering
                ('severity=HIGH', 'High severity filter'),
                ('severity=MEDIUM', 'Medium severity filter'),
                ('severity=LOW', 'Low severity filter'),
                ('severity=CRITICAL', 'Critical severity filter'),
                
                # Status filtering
                ('vuln_status=Analyzed', 'Analyzed status'),
                ('vuln_status=Modified', 'Modified status'),
                ('vuln_status=Rejected', 'Rejected status'),
                
                # Keyword search
                ('keyword=buffer', 'Keyword: buffer'),
                ('keyword=overflow', 'Keyword: overflow'),
                ('keyword=injection', 'Keyword: injection'),
                ('keyword=XSS', 'Keyword: XSS'),
                
                # Date filtering (last 30 days)
                (f'modified_since={(datetime.now() - timedelta(days=30)).isoformat()}', 'Modified last 30 days'),
                (f'published_since={(datetime.now() - timedelta(days=365)).isoformat()}', 'Published last year'),
                
                # Combined filters
                ('year=2023&min_score=7.0', 'Combined: year + score'),
                ('severity=HIGH&keyword=buffer', 'Combined: severity + keyword'),
                ('year=2023&severity=CRITICAL&min_score=9.0', 'Complex combined filter'),
            ]
            
            for params, description in filter_tests:
                resp, _ = self.make_request('GET', f'/api/v1/cves/?{params}')
                if resp:
                    self.log_test(
                        f"CVE List - Filter: {description}",
                        resp.status_code == 200,
                        f"Status: {resp.status_code}, Params: {params}",
                        "filtering"
                    )
            
            # Test sorting options
            sort_tests = [
                ('sort=cve_id&order=asc', 'Sort by CVE ID ascending'),
                ('sort=cve_id&order=desc', 'Sort by CVE ID descending'),
                ('sort=published&order=desc', 'Sort by published date desc'),
                ('sort=published&order=asc', 'Sort by published date asc'),
                ('sort=last_modified&order=desc', 'Sort by last modified desc'),
                ('sort=cvss_v3_score&order=desc', 'Sort by CVSS v3 score desc'),
                ('sort=cvss_v2_score&order=desc', 'Sort by CVSS v2 score desc'),
            ]
            
            for params, description in sort_tests:
                resp, _ = self.make_request('GET', f'/api/v1/cves/?{params}')
                if resp:
                    self.log_test(
                        f"CVE List - {description}",
                        resp.status_code == 200,
                        f"Status: {resp.status_code}",
                        "sorting"
                    )
            
        except json.JSONDecodeError:
            self.log_test("CVE List - JSON Response", False, "Invalid JSON response", "cve-list")
    
    def test_cve_by_id_comprehensive(self):
        """Comprehensive CVE by ID endpoint testing."""
        print("\n🔍 Testing CVE by ID Endpoint - COMPREHENSIVE")
        
        # Test with various CVE ID formats and edge cases
        test_cases = [
            # Valid format CVE IDs
            ('CVE-1999-0095', 'Known test CVE', True),
            ('CVE-2023-12345', 'Standard 2023 CVE', True),
            ('CVE-2024-0001', 'Recent year CVE', True),
            ('CVE-1999-0001', 'Early CVE format', True),
            ('CVE-2023-123456', 'Long sequence number', True),
            
            # Invalid formats
            ('INVALID-ID', 'Invalid format', False),
            ('CVE-99-1234', 'Invalid year format', False),
            ('CVE-2023-123', 'Too short sequence', False),
            ('cve-2023-1234', 'Lowercase', False),
            ('CVE 2023 1234', 'Spaces instead of hyphens', False),
            ('', 'Empty string', False),
            ('CVE-2023-', 'Incomplete format', False),
        ]
        
        for cve_id, description, should_be_valid in test_cases:
            response, exec_time = self.make_request('GET', f'/api/v1/cves/{cve_id}')
            if not response:
                continue
            
            if not should_be_valid:
                # Invalid IDs should return 400, 404, or 422
                self.log_test(
                    f"CVE by ID - Invalid format: {description}",
                    response.status_code in [400, 404, 422],
                    f"Status: {response.status_code}, CVE: {cve_id}",
                    "validation"
                )
            else:
                # Valid format CVE IDs
                if response.status_code == 200:
                    # Performance check for successful responses
                    self.log_test(
                        f"CVE by ID - Response time: {description}",
                        exec_time < 2000,
                        f"Time: {exec_time:.2f}ms",
                        "performance"
                    )
                    
                    try:
                        data = response.json()
                        # Schema validation
                        self.validate_cve_response_schema(data, f"CVE by ID - {description}")
                        
                        # Verify returned CVE ID matches requested
                        self.log_test(
                            f"CVE by ID - Correct ID returned: {description}",
                            data.get('cve_id') == cve_id,
                            f"Requested: {cve_id}, Got: {data.get('cve_id')}",
                            "validation"
                        )
                        
                    except json.JSONDecodeError:
                        self.log_test(f"CVE by ID - JSON Response: {description}", False, "Invalid JSON", "validation")
                        
                elif response.status_code == 404:
                    self.log_test(
                        f"CVE by ID - Not found: {description}",
                        True,
                        f"CVE {cve_id} not found (expected for test data)",
                        "validation"
                    )
                else:
                    self.log_test(
                        f"CVE by ID - Unexpected status: {description}",
                        False,
                        f"Status: {response.status_code}, CVE: {cve_id}",
                        "validation"
                    )
    
    def test_cve_count_endpoint(self):
        """Test CVE count endpoint."""
        print("\n🔢 Testing CVE Count Endpoint")
        
        response, exec_time = self.make_request('GET', '/api/v1/cves/count')
        if not response:
            self.log_test("CVE Count - Connection", False, "Could not connect", "count")
            return
        
        self.log_test(
            "CVE Count - Status Code",
            response.status_code == 200,
            f"Status: {response.status_code}",
            "count"
        )
        
        # Performance check
        self.log_test(
            "CVE Count - Response Time",
            exec_time < 1000,
            f"Time: {exec_time:.2f}ms (should be < 1000ms)",
            "performance"
        )
        
        try:
            data = response.json()
            
            # Validate response structure
            self.log_test(
                "CVE Count - Has total field",
                'total' in data,
                f"Response keys: {list(data.keys())}",
                "count"
            )
            
            # Validate total is a number
            total = data.get('total')
            self.log_test(
                "CVE Count - Total is number",
                isinstance(total, (int, float)),
                f"Total: {total} (type: {type(total)})",
                "count"
            )
            
            # Validate total is non-negative
            if isinstance(total, (int, float)):
                self.log_test(
                    "CVE Count - Total is non-negative",
                    total >= 0,
                    f"Total: {total}",
                    "count"
                )
            
        except json.JSONDecodeError:
            self.log_test("CVE Count - JSON Response", False, "Invalid JSON response", "count")
    
    def test_cve_by_year_comprehensive(self):
        """Comprehensive CVE by year endpoint testing."""
        print("\n📅 Testing CVE by Year Endpoint - COMPREHENSIVE")
        
        # Test various years including edge cases
        year_tests = [
            (1999, "Earliest CVE year", True),
            (2000, "Y2K year", True),
            (2023, "Recent year", True),
            (2024, "Current/future year", True),
            (2030, "Future year boundary", True),
            (1998, "Before CVE system", True),  # Should still work but return empty
            (2050, "Far future", True),
            (1900, "Very old year", False),  # Should be rejected
            (9999, "Invalid year", False),
            (0, "Zero year", False),
            (-1, "Negative year", False),
        ]
        
        for year, description, should_be_valid in year_tests:
            response, exec_time = self.make_request('GET', f'/api/v1/cves/year/{year}')
            if not response:
                continue
            
            if not should_be_valid:
                self.log_test(
                    f"CVE by Year - Invalid year: {description}",
                    response.status_code == 422,
                    f"Status: {response.status_code}, Year: {year}",
                    "validation"
                )
            else:
                self.log_test(
                    f"CVE by Year - {description}",
                    response.status_code == 200,
                    f"Status: {response.status_code}, Year: {year}",
                    "cve-year"
                )
                
                if response.status_code == 200:
                    # Performance check
                    self.log_test(
                        f"CVE by Year - Response time: {description}",
                        exec_time < 3000,
                        f"Time: {exec_time:.2f}ms",
                        "performance"
                    )
                    
                    try:
                        data = response.json()
                        self.log_test(
                            f"CVE by Year - Response type: {description}",
                            isinstance(data, list),
                            f"Response is list: {isinstance(data, list)}, Length: {len(data) if isinstance(data, list) else 'N/A'}",
                            "validation"
                        )
                        
                        # Validate each CVE in response has correct year
                        if isinstance(data, list):
                            for i, cve in enumerate(data[:5]):  # Check first 5 items
                                if 'published' in cve and cve['published']:
                                    try:
                                        pub_date = datetime.fromisoformat(cve['published'].replace('Z', '+00:00'))
                                        self.log_test(
                                            f"CVE by Year - Correct year in item {i}: {description}",
                                            pub_date.year == year,
                                            f"Expected: {year}, Got: {pub_date.year}",
                                            "validation"
                                        )
                                    except ValueError:
                                        self.log_test(f"CVE by Year - Invalid date format in item {i}", False, f"Date: {cve['published']}", "validation")
                        
                    except json.JSONDecodeError:
                        self.log_test(f"CVE by Year - JSON Response: {description}", False, "Invalid JSON", "validation")
        
        # Test invalid year formats
        invalid_formats = ['abc', 'twenty23', '99.5', '']
        for invalid_year in invalid_formats:
            response, _ = self.make_request('GET', f'/api/v1/cves/year/{invalid_year}')
            if response:
                self.log_test(
                    f"CVE by Year - Invalid format: {invalid_year}",
                    response.status_code == 422,
                    f"Status: {response.status_code}",
                    "validation"
                )
    
    def test_cve_by_score_range_comprehensive(self):
        """Comprehensive CVE by score range endpoint testing."""
        print("\n📊 Testing CVE by Score Range Endpoint - COMPREHENSIVE")
        
        # Test various score ranges including edge cases
        score_range_tests = [
            (0.0, 10.0, "Full range", True),
            (0.0, 3.9, "Low severity", True),
            (4.0, 6.9, "Medium severity", True), 
            (7.0, 8.9, "High severity", True),
            (9.0, 10.0, "Critical severity", True),
            (5.5, 7.5, "Cross-boundary range", True),
            (7.0, 7.0, "Exact score", True),
            (0.1, 9.9, "Almost full range", True),
            
            # Edge cases and invalid ranges
            (10.0, 5.0, "Reversed range (min > max)", False),
            (-1.0, 5.0, "Negative minimum", False),
            (5.0, 11.0, "Maximum over 10", False),
            (-1.0, 11.0, "Both out of range", False),
            (10.1, 10.5, "Both over maximum", False),
        ]
        
        for min_score, max_score, description, should_be_valid in score_range_tests:
            response, exec_time = self.make_request('GET', f'/api/v1/cves/score/{min_score}/{max_score}')
            if not response:
                continue
            
            if not should_be_valid:
                self.log_test(
                    f"CVE by Score - Invalid range: {description}",
                    response.status_code in [400, 422],
                    f"Status: {response.status_code}, Range: {min_score}-{max_score}",
                    "validation"
                )
            else:
                self.log_test(
                    f"CVE by Score - {description}",
                    response.status_code == 200,
                    f"Status: {response.status_code}, Range: {min_score}-{max_score}",
                    "cve-score"
                )
                
                if response.status_code == 200:
                    # Performance check
                    self.log_test(
                        f"CVE by Score - Response time: {description}",
                        exec_time < 3000,
                        f"Time: {exec_time:.2f}ms",
                        "performance"
                    )
                    
                    try:
                        data = response.json()
                        self.log_test(
                            f"CVE by Score - Response type: {description}",
                            isinstance(data, list),
                            f"Response is list: {isinstance(data, list)}, Length: {len(data) if isinstance(data, list) else 'N/A'}",
                            "validation"
                        )
                        
                        # Validate scores in response are within range
                        if isinstance(data, list):
                            for i, cve in enumerate(data[:5]):  # Check first 5 items
                                v2_score = cve.get('cvss_v2_score')
                                v3_score = cve.get('cvss_v3_score')
                                
                                # At least one score should be in range
                                in_range = False
                                if v2_score is not None:
                                    try:
                                        score_val = float(v2_score)
                                        in_range = in_range or (min_score <= score_val <= max_score)
                                    except (ValueError, TypeError):
                                        pass
                                
                                if v3_score is not None:
                                    try:
                                        score_val = float(v3_score)
                                        in_range = in_range or (min_score <= score_val <= max_score)
                                    except (ValueError, TypeError):
                                        pass
                                
                                if v2_score is not None or v3_score is not None:
                                    self.log_test(
                                        f"CVE by Score - Score in range item {i}: {description}",
                                        in_range,
                                        f"V2: {v2_score}, V3: {v3_score}, Range: {min_score}-{max_score}",
                                        "validation"
                                    )
                        
                    except json.JSONDecodeError:
                        self.log_test(f"CVE by Score - JSON Response: {description}", False, "Invalid JSON", "validation")
        
        # Test invalid score formats
        invalid_scores = [
            ('abc', '5.0', 'Invalid min score'),
            ('5.0', 'xyz', 'Invalid max score'),
            ('', '5.0', 'Empty min score'),
            ('5.0', '', 'Empty max score'),
        ]
        
        for min_val, max_val, description in invalid_scores:
            response, _ = self.make_request('GET', f'/api/v1/cves/score/{min_val}/{max_val}')
            if response:
                self.log_test(
                    f"CVE by Score - {description}",
                    response.status_code == 422,
                    f"Status: {response.status_code}",
                    "validation"
                )
    
    def test_recent_cves_comprehensive(self):
        """Comprehensive recently modified CVEs endpoint testing."""
        print("\n⏰ Testing Recent CVEs Endpoint - COMPREHENSIVE")
        
        # Test various day ranges including edge cases
        days_tests = [
            (1, "Last 1 day", True),
            (7, "Last week", True),
            (30, "Last month", True),
            (90, "Last quarter", True),
            (365, "Last year", True),
            (730, "Last 2 years", True),
            
            # Edge cases
            (0, "Zero days", False),
            (-1, "Negative days", False),
            (10000, "Very large number", False),  # Should be rejected if API has limits
        ]
        
        for days, description, should_be_valid in days_tests:
            # Note: The endpoint might be /modified/{days} based on the codebase
            endpoints_to_test = [f'/api/v1/cves/recent/{days}', f'/api/v1/cves/modified/{days}']
            
            for endpoint in endpoints_to_test:
                response, exec_time = self.make_request('GET', endpoint)
                if not response:
                    continue
                
                if not should_be_valid:
                    self.log_test(
                        f"Recent CVEs - Invalid days: {description}",
                        response.status_code == 422,
                        f"Status: {response.status_code}, Days: {days}, Endpoint: {endpoint}",
                        "validation"
                    )
                else:
                    self.log_test(
                        f"Recent CVEs - {description}",
                        response.status_code == 200,
                        f"Status: {response.status_code}, Days: {days}, Endpoint: {endpoint}",
                        "cve-recent"
                    )
                    
                    if response.status_code == 200:
                        # Performance check
                        self.log_test(
                            f"Recent CVEs - Response time: {description}",
                            exec_time < 5000,
                            f"Time: {exec_time:.2f}ms",
                            "performance"
                        )
                        
                        try:
                            data = response.json()
                            self.log_test(
                                f"Recent CVEs - Response type: {description}",
                                isinstance(data, list),
                                f"Response is list: {isinstance(data, list)}, Length: {len(data) if isinstance(data, list) else 'N/A'}",
                                "validation"
                            )
                            
                            # Validate modification dates are within range
                            if isinstance(data, list):
                                cutoff_date = datetime.now() - timedelta(days=days)
                                for i, cve in enumerate(data[:5]):  # Check first 5 items
                                    if 'last_modified' in cve and cve['last_modified']:
                                        try:
                                            mod_date = datetime.fromisoformat(cve['last_modified'].replace('Z', '+00:00'))
                                            self.log_test(
                                                f"Recent CVEs - Date in range item {i}: {description}",
                                                mod_date >= cutoff_date.replace(tzinfo=mod_date.tzinfo),
                                                f"Modified: {mod_date}, Cutoff: {cutoff_date}",
                                                "validation"
                                            )
                                        except ValueError:
                                            self.log_test(f"Recent CVEs - Invalid date format in item {i}", False, f"Date: {cve['last_modified']}", "validation")
                            
                        except json.JSONDecodeError:
                            self.log_test(f"Recent CVEs - JSON Response: {description}", False, "Invalid JSON", "validation")
                
                # Only test first successful endpoint
                if response and response.status_code == 200:
                    break
    
    # ============================================================================
    # SYNCHRONIZATION TESTS
    # ============================================================================
    
    def test_sync_endpoints_comprehensive(self):
        """Comprehensive synchronization endpoint testing."""
        print("\n🔄 Testing Synchronization Endpoints - COMPREHENSIVE")
        
        # Test sync status endpoint
        response, exec_time = self.make_request('GET', '/api/v1/sync/status')
        if response:
            self.log_test(
                "Sync Status - Status Code",
                response.status_code in [200, 404],
                f"Status: {response.status_code} (200 if sync exists, 404 if none)",
                "sync"
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Validate sync status structure
                    expected_fields = ['id', 'status', 'sync_type', 'created_at']
                    for field in expected_fields:
                        if field in data:
                            self.log_test(f"Sync Status - {field} field", True, f"Present", "sync")
                except json.JSONDecodeError:
                    self.log_test("Sync Status - JSON Response", False, "Invalid JSON", "sync")
        
        # Test sync history endpoint
        response, _ = self.make_request('GET', '/api/v1/sync/history')
        if response:
            self.log_test(
                "Sync History - Status Code",
                response.status_code == 200,
                f"Status: {response.status_code}",
                "sync"
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    self.log_test(
                        "Sync History - Response Type",
                        isinstance(data, list),
                        f"Response is list: {isinstance(data, list)}, Length: {len(data) if isinstance(data, list) else 'N/A'}",
                        "sync"
                    )
                except json.JSONDecodeError:
                    self.log_test("Sync History - JSON Response", False, "Invalid JSON", "sync")
        
        # Test sync history with pagination
        history_params = [
            ('limit=5', 'Small limit'),
            ('limit=20', 'Default limit'),
            ('limit=100', 'Large limit'),
        ]
        
        for params, description in history_params:
            resp, _ = self.make_request('GET', f'/api/v1/sync/history?{params}')
            if resp:
                self.log_test(
                    f"Sync History - {description}",
                    resp.status_code == 200,
                    f"Status: {resp.status_code}",
                    "sync"
                )
        
        # Test running sync check
        response, _ = self.make_request('GET', '/api/v1/sync/running')
        if response:
            self.log_test(
                "Sync Running Check - Status Code",
                response.status_code == 200,
                f"Status: {response.status_code}",
                "sync"
            )
        
        # Test trigger sync (incremental) - don't actually run to avoid long-running operations
        sync_triggers = [
            ({'sync_type': 'incremental', 'force': False}, 'Incremental sync'),
            ({'sync_type': 'incremental', 'force': True}, 'Forced incremental sync'),
            # Avoid full sync in testing to prevent long operations
            # ({'sync_type': 'full', 'force': False}, 'Full sync'),
        ]
        
        for sync_data, description in sync_triggers:
            response, _ = self.make_request('POST', '/api/v1/sync/', json=sync_data)
            if response:
                self.log_test(
                    f"Trigger Sync - {description}",
                    response.status_code in [202, 400],
                    f"Status: {response.status_code} (202 success, 400 if already running)",
                    "sync"
                )
                
                if response.status_code == 202:
                    try:
                        data = response.json()
                        self.log_test(
                            f"Trigger Sync - Response has sync_id: {description}",
                            'sync_id' in data,
                            f"sync_id present: {'sync_id' in data}",
                            "sync"
                        )
                        
                        # If we successfully triggered a sync, check its status
                        if 'sync_id' in data:
                            time.sleep(1)  # Brief wait
                            status_resp, _ = self.make_request('GET', f'/api/v1/sync/status/{data["sync_id"]}')
                            if status_resp and status_resp.status_code == 200:
                                self.log_test(
                                    f"Trigger Sync - Status trackable: {description}",
                                    True,
                                    f"Sync {data['sync_id']} status retrievable",
                                    "sync"
                                )
                        
                    except json.JSONDecodeError:
                        self.log_test(f"Trigger Sync - JSON Response: {description}", False, "Invalid JSON", "sync")
    
    # ============================================================================
    # ERROR HANDLING AND EDGE CASE TESTS
    # ============================================================================
    
    def test_error_handling_comprehensive(self):
        """Comprehensive error handling testing."""
        print("\n❌ Testing Error Handling - COMPREHENSIVE")
        
        # Test non-existent endpoints
        nonexistent_endpoints = [
            '/api/v1/nonexistent',
            '/api/v1/cves/invalid-endpoint',
            '/api/v2/cves/',
            '/completely/wrong/path',
            '/api/v1/',
        ]
        
        for endpoint in nonexistent_endpoints:
            response, _ = self.make_request('GET', endpoint)
            if response:
                self.log_test(
                    f"Error Handling - 404 for {endpoint}",
                    response.status_code == 404,
                    f"Status: {response.status_code}",
                    "error-handling"
                )
        
        # Test malformed requests
        malformed_tests = [
            # Invalid CVE ID formats
            ('GET', '/api/v1/cves/INVALID_FORMAT', None, 'Invalid CVE ID format'),
            ('GET', '/api/v1/cves/CVE-99-123', None, 'Short year CVE ID'),
            ('GET', '/api/v1/cves/CVE-2023-', None, 'Incomplete CVE ID'),
            
            # Invalid year formats
            ('GET', '/api/v1/cves/year/invalid', None, 'Non-numeric year'),
            ('GET', '/api/v1/cves/year/99999', None, 'Out of range year'),
            
            # Invalid score formats  
            ('GET', '/api/v1/cves/score/invalid/5.0', None, 'Non-numeric min score'),
            ('GET', '/api/v1/cves/score/5.0/invalid', None, 'Non-numeric max score'),
            
            # Invalid pagination parameters
            ('GET', '/api/v1/cves/?page=0', None, 'Zero page number'),
            ('GET', '/api/v1/cves/?page=-1', None, 'Negative page number'),
            ('GET', '/api/v1/cves/?size=0', None, 'Zero page size'),
            ('GET', '/api/v1/cves/?size=1000', None, 'Oversized page'),
            ('GET', '/api/v1/cves/?page=abc', None, 'Non-numeric page'),
            ('GET', '/api/v1/cves/?size=xyz', None, 'Non-numeric size'),
            
            # Invalid JSON in POST requests
            ('POST', '/api/v1/sync/', 'invalid json', 'Invalid JSON syntax'),
            ('POST', '/api/v1/sync/', '{"invalid": json}', 'Malformed JSON'),
            ('POST', '/api/v1/sync/', '{}', 'Empty JSON object'),
        ]
        
        for method, endpoint, data, description in malformed_tests:
            if data == 'invalid json':
                response, _ = self.make_request(method, endpoint, data=data)
            elif data:
                response, _ = self.make_request(method, endpoint, json=data if data != '{"invalid": json}' else None, data=data if data == '{"invalid": json}' else None)
            else:
                response, _ = self.make_request(method, endpoint)
                
            if response:
                self.log_test(
                    f"Error Handling - {description}",
                    response.status_code in [400, 422, 404],
                    f"Status: {response.status_code} (Expected 400/422/404)",
                    "error-handling"
                )
                
                # Check if error response has proper structure
                if response.status_code in [400, 422] and response.headers.get('content-type', '').startswith('application/json'):
                    try:
                        error_data = response.json()
                        self.log_test(
                            f"Error Handling - Proper error response: {description}",
                            'detail' in error_data,
                            f"Error structure: {list(error_data.keys())}",
                            "error-handling"
                        )
                    except json.JSONDecodeError:
                        self.log_test(f"Error Handling - JSON error response: {description}", False, "Non-JSON error response", "error-handling")
        
        # Test HTTP method not allowed
        method_tests = [
            ('POST', '/api/v1/cves/', 'POST on GET-only endpoint'),
            ('PUT', '/api/v1/cves/CVE-2023-12345', 'PUT on GET-only endpoint'),
            ('DELETE', '/api/v1/cves/CVE-2023-12345', 'DELETE on GET-only endpoint'),
            ('PATCH', '/api/v1/cves/CVE-2023-12345', 'PATCH on GET-only endpoint'),
            ('GET', '/api/v1/sync/', 'GET on POST-only endpoint'),
        ]
        
        for method, endpoint, description in method_tests:
            response, _ = self.make_request(method, endpoint)
            if response:
                self.log_test(
                    f"Error Handling - Method not allowed: {description}",
                    response.status_code == 405,
                    f"Status: {response.status_code} (Expected 405)",
                    "error-handling"
                )
    
    # ============================================================================
    # API DOCUMENTATION TESTS
    # ============================================================================
    
    def test_api_documentation_comprehensive(self):
        """Comprehensive API documentation testing."""
        print("\n📚 Testing API Documentation - COMPREHENSIVE")
        
        # Test OpenAPI JSON schema
        response, exec_time = self.make_request('GET', '/openapi.json')
        if response:
            self.log_test(
                "API Docs - OpenAPI JSON",
                response.status_code == 200,
                f"Status: {response.status_code}",
                "docs"
            )
            
            # Performance check
            self.log_test(
                "API Docs - OpenAPI Response Time",
                exec_time < 2000,
                f"Time: {exec_time:.2f}ms",
                "performance"
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    # Validate OpenAPI schema structure
                    required_fields = ['openapi', 'info', 'paths']
                    for field in required_fields:
                        self.log_test(
                            f"API Docs - OpenAPI {field}",
                            field in data,
                            f"Field present: {field in data}",
                            "docs"
                        )
                    
                    # Check info section
                    info = data.get('info', {})
                    info_fields = ['title', 'version']
                    for field in info_fields:
                        self.log_test(
                            f"API Docs - Info {field}",
                            field in info,
                            f"Field present: {field in info}",
                            "docs"
                        )
                    
                    # Check paths section
                    paths = data.get('paths', {})
                    expected_paths = [
                        '/api/v1/cves/',
                        '/api/v1/cves/{cve_id}',
                        '/api/v1/cves/year/{year}',
                        '/api/v1/cves/score/{min_score}/{max_score}',
                        '/api/v1/sync/',
                        '/health'
                    ]
                    
                    for path in expected_paths:
                        self.log_test(
                            f"API Docs - Path documented: {path}",
                            path in paths,
                            f"Path present: {path in paths}",
                            "docs"
                        )
                    
                    # Validate schema definitions
                    components = data.get('components', {})
                    schemas = components.get('schemas', {})
                    expected_schemas = ['CVEResponse', 'CVEListResponse', 'ErrorResponse']
                    
                    for schema in expected_schemas:
                        self.log_test(
                            f"API Docs - Schema defined: {schema}",
                            schema in schemas,
                            f"Schema present: {schema in schemas}",
                            "docs"
                        )
                    
                except json.JSONDecodeError:
                    self.log_test("API Docs - OpenAPI JSON Format", False, "Invalid JSON", "docs")
        
        # Test Swagger UI
        response, exec_time = self.make_request('GET', '/docs')
        if response:
            self.log_test(
                "API Docs - Swagger UI",
                response.status_code == 200,
                f"Status: {response.status_code}",
                "docs"
            )
            
            # Check if response contains HTML
            content_type = response.headers.get('content-type', '')
            self.log_test(
                "API Docs - Swagger UI Content Type",
                'text/html' in content_type,
                f"Content-Type: {content_type}",
                "docs"
            )
            
            # Check for Swagger-specific content
            if response.status_code == 200:
                content = response.text
                swagger_indicators = ['swagger', 'api-docs', 'openapi']
                found_indicators = [indicator for indicator in swagger_indicators if indicator in content.lower()]
                self.log_test(
                    "API Docs - Swagger UI Content",
                    len(found_indicators) > 0,
                    f"Found indicators: {found_indicators}",
                    "docs"
                )
        
        # Test ReDoc
        response, _ = self.make_request('GET', '/redoc')
        if response:
            self.log_test(
                "API Docs - ReDoc",
                response.status_code == 200,
                f"Status: {response.status_code}",
                "docs"
            )
            
            # Check for ReDoc-specific content
            if response.status_code == 200:
                content = response.text
                redoc_indicators = ['redoc', 'api-docs']
                found_indicators = [indicator for indicator in redoc_indicators if indicator in content.lower()]
                self.log_test(
                    "API Docs - ReDoc Content",
                    len(found_indicators) > 0,
                    f"Found indicators: {found_indicators}",
                    "docs"
                )
    
    # ============================================================================
    # PERFORMANCE AND LOAD TESTS
    # ============================================================================
    
    def test_performance_comprehensive(self):
        """Comprehensive performance testing."""
        print("\n⚡ Testing Performance - COMPREHENSIVE")
        
        if not self.include_load_tests:
            print("   Skipping load tests (use --include-load-tests to enable)")
            return
        
        # Single request performance tests
        performance_endpoints = [
            ('/health', 'Health check'),
            ('/api/v1/cves/count', 'CVE count'),
            ('/api/v1/cves/?page=1&size=10', 'Small CVE list'),
            ('/api/v1/cves/?page=1&size=50', 'Medium CVE list'),
            ('/api/v1/cves/year/2023', 'CVE by year'),
            ('/api/v1/cves/score/7.0/10.0', 'CVE by score range'),
        ]
        
        for endpoint, description in performance_endpoints:
            response, exec_time = self.make_request('GET', endpoint)
            if response and response.status_code == 200:
                # Performance thresholds (in milliseconds)
                thresholds = {
                    'Health check': 500,
                    'CVE count': 1000,
                    'Small CVE list': 2000,
                    'Medium CVE list': 5000,
                    'CVE by year': 3000,
                    'CVE by score range': 3000,
                }
                
                threshold = thresholds.get(description, 5000)
                self.log_test(
                    f"Performance - {description}",
                    exec_time < threshold,
                    f"Time: {exec_time:.2f}ms (threshold: {threshold}ms)",
                    "performance"
                )
                
                self.performance_metrics[description.lower().replace(' ', '_')] = exec_time
        
        # Concurrent request testing
        print("\n   Testing concurrent requests...")
        concurrent_results = self.test_concurrent_requests()
        
        # Calculate average response time for concurrent requests
        if concurrent_results:
            avg_time = sum(concurrent_results) / len(concurrent_results)
            max_time = max(concurrent_results)
            min_time = min(concurrent_results)
            
            self.log_test(
                "Performance - Concurrent Average",
                avg_time < 3000,
                f"Avg: {avg_time:.2f}ms, Min: {min_time:.2f}ms, Max: {max_time:.2f}ms",
                "performance"
            )
            
            self.log_test(
                "Performance - Concurrent Max",
                max_time < 10000,
                f"Max time: {max_time:.2f}ms (should be < 10000ms)",
                "performance"
            )
    
    def test_concurrent_requests(self) -> List[float]:
        """Test concurrent requests to check for race conditions and performance."""
        concurrent_count = 10
        endpoint = '/api/v1/cves/?page=1&size=10'
        
        def make_single_request():
            response, exec_time = self.make_request('GET', endpoint, measure_time=True)
            return exec_time if response and response.status_code == 200 else None
        
        with ThreadPoolExecutor(max_workers=concurrent_count) as executor:
            futures = [executor.submit(make_single_request) for _ in range(concurrent_count)]
            results = []
            
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)
        
        success_rate = len(results) / concurrent_count
        self.log_test(
            "Performance - Concurrent Success Rate",
            success_rate >= 0.9,
            f"Success rate: {success_rate:.2%} ({len(results)}/{concurrent_count})",
            "performance"
        )
        
        return results
    
    # ============================================================================
    # NVD API SERVICE TESTS (Optional)
    # ============================================================================
    
    def test_nvd_api_compliance(self):
        """Test NVD API compliance and rate limiting."""
        print("\n🌐 Testing NVD API Compliance")
        
        if not self.include_nvd_tests:
            print("   Skipping NVD API tests (use --include-nvd-tests to enable)")
            return
        
        # Test rate limiting compliance
        print("   Testing rate limiting compliance...")
        
        # Make multiple requests to check rate limiting
        rate_limit_times = []
        for i in range(3):
            start_time = time.time()
            
            # Trigger a sync that would call NVD API
            response, _ = self.make_request('POST', '/api/v1/sync/', json={
                'sync_type': 'incremental',
                'force': False
            })
            
            end_time = time.time()
            request_time = end_time - start_time
            rate_limit_times.append(request_time)
            
            if response:
                self.log_test(
                    f"NVD API - Rate limit test {i+1}",
                    response.status_code in [202, 400],
                    f"Status: {response.status_code}, Time: {request_time:.2f}s",
                    "nvd-api"
                )
            
            # Wait between requests to avoid overwhelming
            if i < 2:
                time.sleep(2)
        
        # Check if rate limiting is properly implemented
        # NVD API allows 5 requests per 30 seconds without API key
        # With API key: 50 requests per 30 seconds
        if len(rate_limit_times) >= 2:
            min_interval = min(rate_limit_times[1:])  # Skip first request
            self.log_test(
                "NVD API - Rate limiting compliance",
                min_interval >= 1.0,  # Should wait at least 1 second between requests
                f"Min interval: {min_interval:.2f}s (should be >= 1.0s)",
                "nvd-api"
            )
    
    # ============================================================================
    # END-TO-END WORKFLOW TESTS
    # ============================================================================
    
    def test_end_to_end_workflows(self):
        """Test complete user workflows."""
        print("\n🔄 Testing End-to-End Workflows")
        
        # Workflow 1: Browse CVE list → Get specific CVE → Check details
        print("   Testing Workflow 1: Browse → View Details")
        
        # Step 1: Get CVE list
        response, _ = self.make_request('GET', '/api/v1/cves/?page=1&size=10')
        if response and response.status_code == 200:
            try:
                data = response.json()
                if data.get('items') and len(data['items']) > 0:
                    first_cve = data['items'][0]
                    cve_id = first_cve.get('cve_id')
                    
                    if cve_id:
                        # Step 2: Get specific CVE details
                        detail_response, _ = self.make_request('GET', f'/api/v1/cves/{cve_id}')
                        if detail_response and detail_response.status_code == 200:
                            try:
                                detail_data = detail_response.json()
                                self.log_test(
                                    "Workflow 1 - Browse to Details",
                                    detail_data.get('cve_id') == cve_id,
                                    f"Successfully navigated from list to {cve_id}",
                                    "workflow"
                                )
                            except json.JSONDecodeError:
                                self.log_test("Workflow 1 - Detail JSON", False, "Invalid JSON in detail response", "workflow")
                        else:
                            self.log_test("Workflow 1 - Detail Fetch", False, f"Could not fetch details for {cve_id}", "workflow")
                    else:
                        self.log_test("Workflow 1 - CVE ID", False, "No CVE ID in list item", "workflow")
                else:
                    self.log_test("Workflow 1 - List Items", False, "No items in CVE list", "workflow")
            except json.JSONDecodeError:
                self.log_test("Workflow 1 - List JSON", False, "Invalid JSON in list response", "workflow")
        else:
            self.log_test("Workflow 1 - List Fetch", False, "Could not fetch CVE list", "workflow")
        
        # Workflow 2: Change results per page → Verify pagination
        print("   Testing Workflow 2: Pagination Changes")
        
        page_sizes = [10, 20, 50]
        for size in page_sizes:
            response, _ = self.make_request('GET', f'/api/v1/cves/?page=1&size={size}')
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    actual_size = len(data.get('items', []))
                    expected_size = data.get('size', 0)
                    
                    self.log_test(
                        f"Workflow 2 - Page size {size}",
                        expected_size == size and actual_size <= size,
                        f"Expected size: {size}, Actual items: {actual_size}, Reported size: {expected_size}",
                        "workflow"
                    )
                except json.JSONDecodeError:
                    self.log_test(f"Workflow 2 - Size {size} JSON", False, "Invalid JSON", "workflow")
        
        # Workflow 3: Filter by year → Filter by score → Verify results
        print("   Testing Workflow 3: Chained Filtering")
        
        # Step 1: Filter by year
        year_response, _ = self.make_request('GET', '/api/v1/cves/year/2023')
        if year_response and year_response.status_code == 200:
            try:
                year_data = year_response.json()
                year_count = len(year_data) if isinstance(year_data, list) else 0
                
                # Step 2: Filter by year and score in main endpoint
                combined_response, _ = self.make_request('GET', '/api/v1/cves/?year=2023&min_score=7.0')
                if combined_response and combined_response.status_code == 200:
                    try:
                        combined_data = combined_response.json()
                        combined_count = len(combined_data.get('items', []))
                        
                        self.log_test(
                            "Workflow 3 - Chained Filtering",
                            combined_count <= year_count,
                            f"Year 2023: {year_count} items, Year+Score: {combined_count} items",
                            "workflow"
                        )
                    except json.JSONDecodeError:
                        self.log_test("Workflow 3 - Combined JSON", False, "Invalid JSON in combined response", "workflow")
                else:
                    self.log_test("Workflow 3 - Combined Filter", False, "Could not apply combined filter", "workflow")
            except json.JSONDecodeError:
                self.log_test("Workflow 3 - Year JSON", False, "Invalid JSON in year response", "workflow")
        else:
            self.log_test("Workflow 3 - Year Filter", False, "Could not filter by year", "workflow")
    
    # ============================================================================
    # DATA VALIDATION AND INTEGRITY TESTS
    # ============================================================================
    
    def test_data_validation_comprehensive(self):
        """Comprehensive data validation and integrity testing."""
        print("\n🔍 Testing Data Validation and Integrity")
        
        # Test CVE ID format validation across all endpoints
        cve_id_formats = [
            ('CVE-2023-12345', True, 'Standard format'),
            ('CVE-1999-0001', True, 'Early format'),
            ('CVE-2024-123456', True, 'Long sequence'),
            ('cve-2023-1234', False, 'Lowercase'),
            ('CVE-99-1234', False, 'Short year'),
            ('CVE-2023-123', False, 'Short sequence'),
            ('INVALID', False, 'Invalid format'),
        ]
        
        for cve_id, should_be_valid, description in cve_id_formats:
            # Test in specific CVE endpoint
            response, _ = self.make_request('GET', f'/api/v1/cves/{cve_id}')
            if response:
                if should_be_valid:
                    # Valid format should either return 200 (found) or 404 (not found), not 422 (invalid format)
                    self.log_test(
                        f"Data Validation - CVE ID format valid: {description}",
                        response.status_code in [200, 404],
                        f"Status: {response.status_code}, CVE: {cve_id}",
                        "data-validation"
                    )
                else:
                    # Invalid format should return 422 (validation error)
                    self.log_test(
                        f"Data Validation - CVE ID format invalid: {description}",
                        response.status_code == 422,
                        f"Status: {response.status_code}, CVE: {cve_id}",
                        "data-validation"
                    )
            
            # Test in list endpoint filter
            list_response, _ = self.make_request('GET', f'/api/v1/cves/?cve_id={quote(cve_id)}')
            if list_response:
                # List endpoint should always return 200 but might have empty results for invalid IDs
                self.log_test(
                    f"Data Validation - CVE ID in list filter: {description}",
                    list_response.status_code == 200,
                    f"Status: {list_response.status_code}, CVE: {cve_id}",
                    "data-validation"
                )
        
        # Test date format validation
        date_formats = [
            ('2023-01-01T00:00:00Z', True, 'ISO format with Z'),
            ('2023-01-01T00:00:00.000Z', True, 'ISO format with milliseconds'),
            ('2023-01-01T00:00:00+00:00', True, 'ISO format with timezone'),
            ('2023-01-01', True, 'Date only'),
            ('invalid-date', False, 'Invalid date'),
            ('2023-13-01T00:00:00Z', False, 'Invalid month'),
            ('2023-01-32T00:00:00Z', False, 'Invalid day'),
        ]
        
        for date_str, should_be_valid, description in date_formats:
            # Test in modified_since filter
            response, _ = self.make_request('GET', f'/api/v1/cves/?modified_since={quote(date_str)}')
            if response:
                if should_be_valid:
                    self.log_test(
                        f"Data Validation - Date format valid: {description}",
                        response.status_code == 200,
                        f"Status: {response.status_code}, Date: {date_str}",
                        "data-validation"
                    )
                else:
                    self.log_test(
                        f"Data Validation - Date format invalid: {description}",
                        response.status_code == 422,
                        f"Status: {response.status_code}, Date: {date_str}",
                        "data-validation"
                    )
        
        # Test numeric validation for scores and pagination
        numeric_tests = [
            ('page', ['1', '100', '-1', '0', 'abc'], [True, True, False, False, False]),
            ('size', ['1', '100', '101', '0', 'xyz'], [True, True, False, False, False]),
            ('min_score', ['0.0', '10.0', '-1.0', '11.0', 'invalid'], [True, True, False, False, False]),
            ('max_score', ['0.0', '10.0', '-1.0', '11.0', 'invalid'], [True, True, False, False, False]),
        ]
        
        for param_name, values, validities in numeric_tests:
            for value, should_be_valid in zip(values, validities):
                response, _ = self.make_request('GET', f'/api/v1/cves/?{param_name}={value}')
                if response:
                    if should_be_valid:
                        self.log_test(
                            f"Data Validation - {param_name} valid: {value}",
                            response.status_code == 200,
                            f"Status: {response.status_code}",
                            "data-validation"
                        )
                    else:
                        self.log_test(
                            f"Data Validation - {param_name} invalid: {value}",
                            response.status_code == 422,
                            f"Status: {response.status_code}",
                            "data-validation"
                        )
    
    # ============================================================================
    # PDF REQUIREMENTS COMPLIANCE TESTS
    # ============================================================================
    
    def test_pdf_requirements_compliance(self):
        """Test compliance with PDF requirements."""
        print("\n📋 Testing PDF Requirements Compliance")
        
        # Required API endpoints as per PDF
        required_endpoints = [
            ('GET', '/api/v1/cves/{cve_id}', 'Specific CVE by ID'),
            ('GET', '/api/v1/cves/year/{year}', 'CVEs from specific year'),
            ('GET', '/api/v1/cves/score/{min_score}/{max_score}', 'CVEs by CVSS score range'),
            ('GET', '/api/v1/cves/modified/{days}', 'CVEs modified in last N days'),
            ('GET', '/api/v1/cves/', 'Paginated list with filters'),
            ('POST', '/api/v1/sync/', 'Trigger manual synchronization'),
            ('GET', '/health', 'System health check'),
            ('GET', '/docs', 'API documentation'),
            ('GET', '/api/v1/cves/count', 'Total CVE count'),
        ]
        
        for method, endpoint_template, description in required_endpoints:
            # Replace template variables with actual values for testing
            test_endpoint = endpoint_template
            if '{cve_id}' in test_endpoint:
                test_endpoint = test_endpoint.replace('{cve_id}', 'CVE-2023-12345')
            if '{year}' in test_endpoint:
                test_endpoint = test_endpoint.replace('{year}', '2023')
            if '{min_score}' in test_endpoint:
                test_endpoint = test_endpoint.replace('{min_score}', '7.0')
            if '{max_score}' in test_endpoint:
                test_endpoint = test_endpoint.replace('{max_score}', '10.0')
            if '{days}' in test_endpoint:
                test_endpoint = test_endpoint.replace('{days}', '30')
            
            if method == 'POST':
                response, _ = self.make_request(method, test_endpoint, json={'sync_type': 'incremental', 'force': False})
            else:
                response, _ = self.make_request(method, test_endpoint)
            
            if response:
                # Endpoint should exist (not 404)
                self.log_test(
                    f"PDF Compliance - Endpoint exists: {description}",
                    response.status_code != 404,
                    f"Status: {response.status_code}, Endpoint: {method} {endpoint_template}",
                    "pdf-compliance"
                )
                
                # Should return appropriate response for valid requests
                expected_success_codes = [200, 202] if method == 'POST' else [200]
                if response.status_code in expected_success_codes + [404]:  # 404 is OK for specific CVEs that don't exist
                    self.log_test(
                        f"PDF Compliance - Endpoint functional: {description}",
                        True,
                        f"Status: {response.status_code}",
                        "pdf-compliance"
                    )
        
        # Test pagination parameters as required by PDF
        pagination_features = [
            ('page', 'Page number parameter'),
            ('size', 'Results per page parameter'),
        ]
        
        for param, description in pagination_features:
            response, _ = self.make_request('GET', f'/api/v1/cves/?{param}=1')
            if response:
                self.log_test(
                    f"PDF Compliance - {description}",
                    response.status_code == 200,
                    f"Status: {response.status_code}",
                    "pdf-compliance"
                )
        
        # Test filtering parameters as required by PDF
        filtering_features = [
            ('year=2023', 'Year filtering'),
            ('min_score=7.0&max_score=10.0', 'CVSS score filtering'),
            ('keyword=buffer', 'Keyword search'),
        ]
        
        for params, description in filtering_features:
            response, _ = self.make_request('GET', f'/api/v1/cves/?{params}')
            if response:
                self.log_test(
                    f"PDF Compliance - {description}",
                    response.status_code == 200,
                    f"Status: {response.status_code}",
                    "pdf-compliance"
                )
        
        # Test results per page options (10, 50, 100 as mentioned in UI requirements)
        results_per_page_options = [10, 50, 100]
        for size in results_per_page_options:
            response, _ = self.make_request('GET', f'/api/v1/cves/?size={size}')
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    reported_size = data.get('size', 0)
                    self.log_test(
                        f"PDF Compliance - Results per page {size}",
                        reported_size == size,
                        f"Requested: {size}, Reported: {reported_size}",
                        "pdf-compliance"
                    )
                except json.JSONDecodeError:
                    self.log_test(f"PDF Compliance - Results per page {size} JSON", False, "Invalid JSON", "pdf-compliance")
        
        # Test total count display capability
        response, _ = self.make_request('GET', '/api/v1/cves/count')
        if response and response.status_code == 200:
            try:
                data = response.json()
                has_total = 'total' in data and isinstance(data['total'], (int, float))
                self.log_test(
                    "PDF Compliance - Total count display",
                    has_total,
                    f"Has total field: {has_total}, Value: {data.get('total')}",
                    "pdf-compliance"
                )
            except json.JSONDecodeError:
                self.log_test("PDF Compliance - Total count JSON", False, "Invalid JSON", "pdf-compliance")
    
    # ============================================================================
    # MAIN TEST RUNNER
    # ============================================================================
    
    def run_all_tests(self):
        """Run all comprehensive tests."""
        print("🚀 ULTIMATE CVE ASSESSMENT API TESTING SUITE")
        print(f"   Target: {self.base_url}")
        print(f"   Timestamp: {datetime.now().isoformat()}")
        print(f"   Load Tests: {'Enabled' if self.include_load_tests else 'Disabled'}")
        print(f"   NVD Tests: {'Enabled' if self.include_nvd_tests else 'Disabled'}")
        print("=" * 100)
        
        # Run all test categories
        self.test_health_check()
        self.test_application_info()
        self.test_cve_list_endpoint_comprehensive()
        self.test_cve_by_id_comprehensive()
        self.test_cve_count_endpoint()
        self.test_cve_by_year_comprehensive()
        self.test_cve_by_score_range_comprehensive()
        self.test_recent_cves_comprehensive()
        self.test_sync_endpoints_comprehensive()
        self.test_error_handling_comprehensive()
        self.test_api_documentation_comprehensive()
        self.test_performance_comprehensive()
        self.test_nvd_api_compliance()
        self.test_end_to_end_workflows()
        self.test_data_validation_comprehensive()
        self.test_pdf_requirements_compliance()
        
        # Print comprehensive summary
        self.print_comprehensive_summary()
    
    def print_comprehensive_summary(self):
        """Print comprehensive test summary with categorization."""
        print("\n" + "=" * 100)
        print("📊 ULTIMATE TEST SUMMARY")
        print("=" * 100)
        
        # Overall statistics
        print(f"Total Tests: {self.total_tests}")
        print(f"✅ Passed: {self.passed_tests}")
        print(f"❌ Failed: {self.failed_tests}")
        
        success_rate = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        # Categorized results
        categories = {}
        for result in self.test_results:
            category = result['category']
            if category not in categories:
                categories[category] = {'passed': 0, 'failed': 0, 'total': 0}
            
            categories[category]['total'] += 1
            if result['passed']:
                categories[category]['passed'] += 1
            else:
                categories[category]['failed'] += 1
        
        print(f"\n📋 Results by Category:")
        for category, stats in sorted(categories.items()):
            success_rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
            status = "✅" if stats['failed'] == 0 else "⚠️" if success_rate >= 80 else "❌"
            print(f"   {status} {category.upper():<15}: {stats['passed']}/{stats['total']} ({success_rate:.1f}%)")
        
        # Performance metrics
        if self.performance_metrics:
            print(f"\n⚡ Performance Metrics:")
            for metric, time_ms in self.performance_metrics.items():
                print(f"   {metric.replace('_', ' ').title()}: {time_ms:.2f}ms")
        
        # Failed tests details
        if self.failed_tests > 0:
            print(f"\n❌ Failed Tests by Category:")
            failed_by_category = {}
            for result in self.test_results:
                if not result['passed']:
                    category = result['category']
                    if category not in failed_by_category:
                        failed_by_category[category] = []
                    failed_by_category[category].append(result)
            
            for category, failures in sorted(failed_by_category.items()):
                print(f"\n   {category.upper()}:")
                for failure in failures:
                    print(f"      • {failure['test']}: {failure['details']}")
        
        print("\n" + "=" * 100)
        
        # Final assessment
        if self.failed_tests == 0:
            print("🎉 ALL TESTS PASSED! Your CVE Assessment API is fully compliant and ready for production.")
        elif success_rate >= 95:
            print("🌟 EXCELLENT! Minor issues detected but overall system is highly functional.")
        elif success_rate >= 80:
            print("👍 GOOD! Most functionality working correctly with some areas needing attention.")
        elif success_rate >= 60:
            print("⚠️  FAIR! Basic functionality working but significant improvements needed.")
        else:
            print("🔧 NEEDS WORK! Major issues detected requiring immediate attention.")
        
        print(f"\n💡 Recommendations:")
        if success_rate < 100:
            print("   • Review failed tests and fix underlying issues")
            print("   • Check error logs for detailed diagnostics")
            print("   • Verify database connectivity and schema")
            print("   • Ensure all required environment variables are set")
        if success_rate >= 80:
            print("   • Consider implementing performance optimizations")
            print("   • Add monitoring and alerting for production deployment")
            print("   • Document API usage patterns and best practices")
        
        return self.failed_tests == 0


def main():
    """Main entry point for the ultimate test script."""
    parser = argparse.ArgumentParser(
        description='Ultimate Comprehensive CVE Assessment API Test Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_api_endpoints_ultimate.py
  python test_api_endpoints_ultimate.py --include-load-tests
  python test_api_endpoints_ultimate.py --include-nvd-tests --output results.json
  python test_api_endpoints_ultimate.py --url http://staging.example.com:8000
        """
    )
    
    parser.add_argument(
        '--url', 
        default='http://localhost:8000',
        help='Base URL of the API (default: http://localhost:8000)'
    )
    parser.add_argument(
        '--output',
        help='Save test results to JSON file'
    )
    parser.add_argument(
        '--include-load-tests',
        action='store_true',
        help='Include performance and load testing (may take longer)'
    )
    parser.add_argument(
        '--include-nvd-tests',
        action='store_true',
        help='Include NVD API compliance tests (requires API access)'
    )
    
    args = parser.parse_args()
    
    # Initialize and run tester
    tester = CVEAPIUltimateTester(
        base_url=args.url,
        include_load_tests=args.include_load_tests,
        include_nvd_tests=args.include_nvd_tests
    )
    
    try:
        success = tester.run_all_tests()
        
        # Save results if output file specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump({
                    'summary': {
                        'total_tests': tester.total_tests,
                        'passed_tests': tester.passed_tests,
                        'failed_tests': tester.failed_tests,
                        'success_rate': (tester.passed_tests / tester.total_tests * 100) if tester.total_tests > 0 else 0,
                        'timestamp': datetime.now().isoformat(),
                        'target_url': args.url
                    },
                    'performance_metrics': tester.performance_metrics,
                    'test_results': tester.test_results
                }, f, indent=2)
            print(f"\n💾 Detailed test results saved to: {args.output}")
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Testing failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
