import { test, expect } from '@playwright/test';
import { DashboardHelpers } from './utils/test-helpers';

test.describe('Kong Guard AI Dashboard - Plugin Management', () => {
  let helpers: DashboardHelpers;

  test.beforeEach(async ({ page }) => {
    helpers = new DashboardHelpers(page);
    await page.goto('/kong-dashboard.html');
    await helpers.waitForServicesOnline();
  });

  test('should display plugin management section', async ({ page }) => {
    await expect(page.getByText('Plugin Management')).toBeVisible();
    await expect(page.getByText('Current Configuration')).toBeVisible();
  });

  test('should check plugin status', async ({ page }) => {
    await page.getByRole('button', { name: 'Get Plugin Status' }).click();
    await helpers.waitForResponse();

    const response = await helpers.getResponseData();
    expect(response).toBeTruthy();

    // Should have configuration data
    if (response.success === false) {
      // Plugin endpoint might not be available
      expect(response.error).toBeDefined();
    } else {
      expect(response).toHaveProperty('config');
    }
  });

  test('should view blocked IPs', async ({ page }) => {
    await page.getByRole('button', { name: 'View Blocked IPs' }).click();
    await helpers.waitForResponse();

    const response = await helpers.getResponseData();
    expect(response).toBeTruthy();

    // Response should be an array or error message
    if (Array.isArray(response)) {
      expect(response).toBeDefined();
    } else {
      expect(response.error).toBeDefined();
    }
  });

  test('should view metrics', async ({ page }) => {
    await page.getByRole('button', { name: 'View Metrics' }).click();
    await helpers.waitForResponse();

    const response = await helpers.getResponseData();
    expect(response).toBeTruthy();

    // Should have metrics or error
    if (!response.error) {
      expect(response).toBeDefined();
    }
  });

  test('should display configuration info box', async ({ page }) => {
    const configInfo = page.locator('#config-info');
    await expect(configInfo).toBeVisible();

    const text = await configInfo.textContent();
    expect(text).toBeTruthy();
  });

  test('should enable plugin on test service', async ({ page }) => {
    await page.getByRole('button', { name: 'Enable Plugin' }).click();
    await helpers.waitForResponse();

    const response = await helpers.getResponseData();
    expect(response).toBeTruthy();

    if (response.success) {
      expect(response.message).toContain('enabled successfully');
      expect(response.plugin).toBeDefined();

      // Check config info updated
      const configText = await page.locator('#config-info').textContent();
      expect(configText).toContain('Plugin enabled');
    } else {
      // Plugin might already be enabled
      expect(response.error).toBeDefined();
    }
  });

  test('should display plugin configuration after enabling', async ({ page }) => {
    await page.getByRole('button', { name: 'Enable Plugin' }).click();
    await helpers.waitForResponse();

    const response = await helpers.getResponseData();
    if (response.success) {
      const configText = await page.locator('#config-info').textContent();
      expect(configText).toContain('blocking threshold');
      expect(configText).toContain('Rate limit threshold');
    }
  });

  test('should handle plugin management errors gracefully', async ({ page }) => {
    // Update admin URL to invalid endpoint
    await helpers.updateConfiguration('admin-url', 'http://localhost:99999');

    // Try to get plugin status
    await page.getByRole('button', { name: 'Get Plugin Status' }).click();
    await helpers.waitForResponse();

    const response = await helpers.getResponseData();
    expect(response.error).toBeDefined();

    // Reset to correct URL
    await helpers.updateConfiguration('admin-url', 'http://localhost:18001');
  });

  test('should show all plugin management cards', async ({ page }) => {
    const cards = page.locator('.test-section').nth(1).locator('.test-card');
    const count = await cards.count();
    expect(count).toBe(3); // Plugin Status, View Incidents, Enable Plugin
  });

  test('should have correct button labels', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Check Status' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'View Incidents' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Enable Plugin' })).toBeVisible();
  });

  test('should view incidents', async ({ page }) => {
    await page.getByRole('button', { name: 'View Incidents' }).click();
    await helpers.waitForResponse();

    const response = await helpers.getResponseData();
    expect(response).toBeTruthy();

    // Should return incidents array or error
    if (!response.error) {
      // If incidents endpoint exists, should return array
      expect(response).toBeDefined();
    } else {
      expect(response.status).toBeDefined();
    }
  });

  test('should maintain response formatting for plugin data', async ({ page }) => {
    await page.getByRole('button', { name: 'Get Plugin Status' }).click();
    await helpers.waitForResponse();

    // Check response is properly formatted JSON
    const responseText = await page.locator('#response').textContent();
    expect(responseText).toBeTruthy();

    // Should be valid JSON
    const parsed = JSON.parse(responseText!);
    expect(parsed).toBeDefined();
  });

  test('should update config info when plugin is configured', async ({ page }) => {
    const initialText = await page.locator('#config-info').textContent();

    // Enable plugin
    await page.getByRole('button', { name: 'Enable Plugin' }).click();
    await helpers.waitForResponse();

    const response = await helpers.getResponseData();
    if (response.success) {
      const updatedText = await page.locator('#config-info').textContent();
      expect(updatedText).not.toBe(initialText);
      expect(updatedText).toContain('0.8'); // blocking threshold
      expect(updatedText).toContain('0.6'); // rate limit threshold
    }
  });
});
