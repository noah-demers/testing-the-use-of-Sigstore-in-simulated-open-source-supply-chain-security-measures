#!/usr/bin/env python3
import time
import os
import subprocess
from kam_client import KAMService

def test_kam_service():
    print("🔑 Testing KAM service...")
    try:
        kam = KAMService()
        result = kam.authorize_key("test_package", "test@example.com", 3600)
        assert result["status"] == "ok"
        check_result = kam.check_key("test_package", "test@example.com")
        assert check_result["authorized"] == True
        print("✅ KAM service test passed")
        return True
    except Exception as e:
        print(f"❌ KAM service test failed: {e}")
        return False

def test_publisher():
    print("📦 Testing publisher...")
    try:
        result = subprocess.run([
            "python3", "publisher_improved.py", "--config", "baseline"
        ], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ Baseline publisher test passed")
        else:
            print(f"⚠️  Baseline publisher test failed: {result.stderr}")
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Publisher test failed: {e}")
        return False

def test_consumer():
    print("🔍 Testing consumer...")
    try:
        result = subprocess.run([
            "python3", "consumer.py", "--config", "baseline"
        ], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ Consumer test passed")
        else:
            print(f"⚠️  Consumer test failed: {result.stderr}")
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Consumer test failed: {e}")
        return False

def test_attacker():
    print("Testing attack simulation...")
    try:
        os.environ["EXPERIMENT_CONFIG"] = "baseline"
        from attacker import StolenKeyAttack
        attack = StolenKeyAttack()
        result = attack.execute()
        print(f"✅ Attack simulation test completed (success: {result})")
        return True
    except Exception as e:
        print(f"❌ Attack simulation test failed: {e}")
        return False

def main():
    print("Running Sigstore + KAM Experiment Tests")
    print("=" * 50)
    tests = [
        ("KAM Service", test_kam_service),
        ("Publisher", test_publisher),
        ("Consumer", test_consumer),
        ("Attacker Simulation", test_attacker)
    ]
    results = []
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        success = test_func()
        results.append((test_name, success))
        time.sleep(1)
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    passed = 0
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {test_name:20} {status}")
        if success:
            passed += 1
    print(f"\nTests passed: {passed}/{len(results)}")
    if passed == len(results):
        print("All tests passed. Experiment setup is ready.")
    else:
        print("⚠️  Some tests failed. Check the setup and try again.")
    return passed == len(results)

if __name__ == "__main__":
    main()
