#!/usr/bin/env python3
"""
Test Supabase integration with ai-service
"""
import httpx
import asyncio

async def test_integration():
    print("🧪 Testing Supabase Integration with AI Service")
    print("=" * 60)
    
    # Test endpoints
    base_url = "http://localhost:8000"
    
    async with httpx.AsyncClient() as client:
        # Test 1: List attack runs
        print("\n📋 Test 1: Listing attack runs from Supabase...")
        try:
            response = await client.get(f"{base_url}/api/attack/flood/list", timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                runs = data.get('runs', [])
                print(f"✅ Found {len(runs)} attack runs")
                if runs:
                    print(f"   Latest run: ID {runs[0].get('run_id')}")
            else:
                print(f"❌ Failed: Status {response.status_code}")
        except Exception as e:
            print(f"❌ Connection error: {e}")
            print("   Make sure ai-service is running on port 8000")
            return
        
        # Test 2: Get specific attack run results
        if runs:
            run_id = runs[0].get('run_id')
            print(f"\n📊 Test 2: Getting results for run {run_id}...")
            try:
                response = await client.get(f"{base_url}/api/attack/flood/results/{run_id}", timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Retrieved results:")
                    print(f"   Total attacks: {data.get('total_attacks')}")
                    print(f"   Duration: {data.get('duration')}s")
                else:
                    print(f"❌ Failed: Status {response.status_code}")
            except Exception as e:
                print(f"❌ Error: {e}")
        
        # Test 3: Check database connectivity
        print(f"\n🔍 Test 3: Verifying Supabase connectivity...")
        from supabase_production import SupabaseProduction
        db = SupabaseProduction()
        
        if db.test_connection():
            print("✅ Supabase connection successful")
            
            # Get statistics
            stats = db.get_attack_run_stats()
            if stats['success']:
                print("✅ Can query attack statistics from Supabase")
        else:
            print("❌ Supabase connection failed")
    
    print("\n" + "=" * 60)
    print("🎉 Integration test complete!")
    print("\nNotes:")
    print("- If tests failed, ensure ai-service is running")
    print("- Run: cd ai-service && python3 app.py")
    print("- Supabase is at 198.51.100.201")

if __name__ == "__main__":
    asyncio.run(test_integration())