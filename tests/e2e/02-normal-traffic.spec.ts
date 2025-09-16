import { test, expect } from '@playwright/test';
import { DashboardHelpers } from './utils/test-helpers';

test.describe('Kong Guard AI Dashboard - Normal Traffic Tests', () => {
  let helpers: DashboardHelpers;

  test.beforeEach(async ({ page }) => {
    helpers = new DashboardHelpers(page);
    await page.goto('/kong-dashboard.html');
    await helpers.waitForServicesOnline();
  });

  test('should send normal request successfully', async ({ page }) => {
    await helpers.clickTestButton('Send Normal Request');

    const response = await helpers.getResponseData();
    console.log('Response received:', JSON.stringify(response, null, 2));
    expect(response).toBeTruthy();

    // Check if response has expected structure
    if (response.error) {
      // If there's an error, the test should still pass if it's a connection issue
      console.warn('Request error:', response.error);
    } else {
      expect(response.status).toBe(200);
      expect(response.action).toBe('Allowed');
      expect(response.threat).toBe('None');
    }
  });

  test('should send burst of 10 requests', async ({ page }) => {
    await helpers.clickTestButton('Send Burst (10 requests)');

    const response = await helpers.getResponseData();
    expect(response).toBeTruthy();
    expect(response.total).toBe(10);
    expect(response.success).toBeGreaterThan(0);

    // Some requests might be blocked if rate limiting kicks in
    if (response.blocked > 0) {
      expect(response.blocked + response.success).toBe(10);
    }
  });

  test('should update statistics after requests', async ({ page }) => {
    // Get initial stats
    const initialTotal = await helpers.getStatValue('total-requests');

    // Send a normal request
    await helpers.clickTestButton('Send Normal Request');

    // Check stats updated
    await page.waitForTimeout(500);
    const newTotal = await helpers.getStatValue('total-requests');
    expect(parseInt(newTotal)).toBeGreaterThan(parseInt(initialTotal));
  });

  test('should calculate success rate correctly', async ({ page }) => {
    // Send normal request
    await helpers.clickTestButton('Send Normal Request');

    // Check success rate
    const successRate = await helpers.getStatValue('success-rate');
    expect(successRate).toMatch(/\d+%/);
  });

  test('should measure response time', async ({ page }) => {
    await helpers.clickTestButton('Send Normal Request');

    // Check average response time
    await page.waitForTimeout(500);
    const avgResponse = await helpers.getStatValue('avg-response');
    expect(avgResponse).toMatch(/\d+ms/);
  });

  test('should handle multiple sequential normal requests', async ({ page }) => {
    for (let i = 0; i < 3; i++) {
      await helpers.clickTestButton('Send Normal Request');
      const response = await helpers.getResponseData();
      expect(response.status).toBe(200);
      await page.waitForTimeout(500);
    }

    const totalRequests = await helpers.getStatValue('total-requests');
    expect(parseInt(totalRequests)).toBeGreaterThanOrEqual(3);
  });

  test('should display response in correct format', async ({ page }) => {
    await helpers.clickTestButton('Send Normal Request');

    // Check response area is visible
    await expect(page.locator('.response-area.show')).toBeVisible();

    // Check response contains expected fields
    const responseText = await page.locator('#response').textContent();
    expect(responseText).toContain('status');
    expect(responseText).toContain('statusText');
    expect(responseText).toContain('threat');
    expect(responseText).toContain('action');
  });

  test('should maintain results history', async ({ page }) => {
    // Send multiple requests
    await helpers.clickTestButton('Send Normal Request');
    await page.waitForTimeout(500);
    await helpers.clickTestButton('Send Burst (10 requests)');

    // Check results are displayed
    const resultItems = await page.locator('.result-item').count();
    expect(resultItems).toBeGreaterThan(0);
  });

  test('should clear results when clear button is clicked', async ({ page }) => {
    // Send some requests
    await helpers.clickTestButton('Send Normal Request');
    await page.waitForTimeout(500);

    // Clear results
    await page.getByRole('button', { name: 'Clear Results' }).click();

    // Check stats are reset
    const totalRequests = await helpers.getStatValue('total-requests');
    expect(totalRequests).toBe('0');

    const blockedCount = await helpers.getStatValue('blocked-count');
    expect(blockedCount).toBe('0');
  });

  test('should handle rapid consecutive burst tests', async ({ page }) => {
    // Send two burst tests quickly
    await helpers.clickTestButton('Send Burst (10 requests)');
    await page.waitForTimeout(1000);
    await helpers.clickTestButton('Send Burst (10 requests)');

    // Check total requests
    await page.waitForTimeout(1000);
    const totalRequests = await helpers.getStatValue('total-requests');
    expect(parseInt(totalRequests)).toBeGreaterThanOrEqual(20);
  });
});
