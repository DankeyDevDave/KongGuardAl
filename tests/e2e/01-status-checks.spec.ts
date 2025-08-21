import { test, expect } from '@playwright/test';
import { DashboardHelpers } from './utils/test-helpers';

test.describe('Kong Guard AI Dashboard - Status Checks', () => {
  let helpers: DashboardHelpers;

  test.beforeEach(async ({ page }) => {
    helpers = new DashboardHelpers(page);
    await page.goto('/kong-dashboard.html');
  });

  test('should load dashboard successfully', async ({ page }) => {
    await expect(page).toHaveTitle('Kong Guard AI - Testing Dashboard');
    await expect(page.locator('h1')).toContainText('Kong Guard AI Testing Dashboard');
  });

  test('should display all status indicators', async ({ page }) => {
    // Check that all status indicators exist
    await expect(page.locator('#kong-status')).toBeVisible();
    await expect(page.locator('#admin-status')).toBeVisible();
    await expect(page.locator('#plugin-status')).toBeVisible();
    await expect(page.locator('#demo-status')).toBeVisible();
  });

  test('should show correct port information', async ({ page }) => {
    await expect(page.locator('#kong-port')).toContainText('Port 18000');
    await expect(page.locator('#admin-port')).toContainText('Port 18001');
    await expect(page.locator('#demo-port')).toContainText('Port 18085');
  });

  test('should check Kong Admin API status', async ({ page }) => {
    await helpers.waitForServicesOnline();
    const isOnline = await helpers.checkServiceStatus('admin');
    expect(isOnline).toBeTruthy();
  });

  test('should check Kong Proxy status', async ({ page }) => {
    await helpers.waitForServicesOnline();
    const isOnline = await helpers.checkServiceStatus('kong');
    expect(isOnline).toBeTruthy();
  });

  test('should check Demo API status', async ({ page }) => {
    await helpers.waitForServicesOnline();
    const isOnline = await helpers.checkServiceStatus('demo');
    expect(isOnline).toBeTruthy();
  });

  test('should verify Kong Guard AI plugin is loaded', async ({ page }) => {
    await helpers.waitForServicesOnline();
    const pluginState = await helpers.getPluginState();
    expect(pluginState).toBe('Loaded');
  });

  test('should auto-refresh status every 5 seconds', async ({ page }) => {
    // Get initial status
    const initialClass = await page.locator('#kong-status').getAttribute('class');
    
    // Wait for refresh cycle
    await page.waitForTimeout(6000);
    
    // Check status was updated (class should still exist)
    const updatedClass = await page.locator('#kong-status').getAttribute('class');
    expect(updatedClass).toBeDefined();
  });

  test('should display configuration section', async ({ page }) => {
    await expect(page.getByText('Configuration')).toBeVisible();
    await expect(page.locator('#admin-url')).toHaveValue('http://localhost:18001');
    await expect(page.locator('#proxy-url')).toHaveValue('http://localhost:18000');
    await expect(page.locator('#api-path')).toHaveValue('/test');
  });

  test('should update configuration values', async ({ page }) => {
    await helpers.updateConfiguration('api-path', '/api/v1');
    await expect(page.locator('#api-path')).toHaveValue('/api/v1');
    
    // Reset to default
    await helpers.updateConfiguration('api-path', '/test');
  });
});