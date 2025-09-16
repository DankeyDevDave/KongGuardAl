import { test, expect } from '@playwright/test';
import { DashboardHelpers } from './utils/test-helpers';

test.describe('Kong Guard AI Dashboard - UI Interactions', () => {
  let helpers: DashboardHelpers;

  test.beforeEach(async ({ page }) => {
    helpers = new DashboardHelpers(page);
    await page.goto('/kong-dashboard.html');
    await helpers.waitForServicesOnline();
  });

  test('should have responsive layout', async ({ page }) => {
    // Test different viewport sizes
    const viewports = [
      { width: 1920, height: 1080 }, // Desktop
      { width: 1366, height: 768 },  // Laptop
      { width: 768, height: 1024 },  // Tablet
      { width: 375, height: 667 }    // Mobile
    ];

    for (const viewport of viewports) {
      await page.setViewportSize(viewport);
      await expect(page.locator('h1')).toBeVisible();
      await expect(page.locator('.container')).toBeVisible();
    }
  });

  test('should have proper color scheme and styling', async ({ page }) => {
    // Check gradient background
    const bodyStyle = await page.locator('body').evaluate(el =>
      window.getComputedStyle(el).background
    );
    expect(bodyStyle).toContain('gradient');

    // Check card styling
    const testSection = page.locator('.test-section').first();
    const bgColor = await testSection.evaluate(el =>
      window.getComputedStyle(el).backgroundColor
    );
    expect(bgColor).toBe('rgb(255, 255, 255)'); // white background
  });

  test('should show hover effects on buttons', async ({ page }) => {
    const button = page.getByRole('button', { name: 'Send Normal Request' });

    // Get initial style
    const initialTransform = await button.evaluate(el =>
      window.getComputedStyle(el).transform
    );

    // Hover over button
    await button.hover();

    // Check transform changed (hover effect)
    const hoverTransform = await button.evaluate(el =>
      window.getComputedStyle(el).transform
    );
    expect(hoverTransform).not.toBe(initialTransform);
  });

  test('should display status indicators with animations', async ({ page }) => {
    const indicator = page.locator('.status-indicator').first();

    // Check animation is applied
    const animation = await indicator.evaluate(el =>
      window.getComputedStyle(el).animation
    );
    expect(animation).toContain('pulse');
  });

  test('should show test cards with proper threat level badges', async ({ page }) => {
    // Check HIGH threat badges
    const highThreat = page.locator('.threat-level.high');
    const highCount = await highThreat.count();
    expect(highCount).toBeGreaterThan(0);

    // Check styling
    const highBg = await highThreat.first().evaluate(el =>
      window.getComputedStyle(el).backgroundColor
    );
    expect(highBg).toBe('rgb(239, 68, 68)'); // red color
  });

  test('should display response area with correct visibility toggle', async ({ page }) => {
    const responseArea = page.locator('.response-area');

    // Initially hidden
    let display = await responseArea.evaluate(el =>
      window.getComputedStyle(el).display
    );
    expect(display).toBe('none');

    // Send request to show response
    await helpers.clickTestButton('Send Normal Request');

    // Should be visible now
    await expect(responseArea).toHaveClass(/show/);
    display = await responseArea.evaluate(el =>
      window.getComputedStyle(el).display
    );
    expect(display).toBe('block');
  });

  test('should format JSON response with proper indentation', async ({ page }) => {
    await helpers.clickTestButton('Send Normal Request');

    const responseText = await page.locator('#response').textContent();
    expect(responseText).toContain('\n'); // Has line breaks
    expect(responseText).toMatch(/^\s{2}/m); // Has indentation
  });

  test('should display statistics grid properly', async ({ page }) => {
    const statsGrid = page.locator('.stats-grid');
    await expect(statsGrid).toBeVisible();

    // Check all stat cards are present
    const statCards = statsGrid.locator('.stat-card');
    const count = await statCards.count();
    expect(count).toBe(4);

    // Check stat labels and values
    await expect(page.locator('.stat-label').first()).toBeVisible();
    await expect(page.locator('.stat-value').first()).toBeVisible();
  });

  test('should have accessible form inputs', async ({ page }) => {
    // Check labels are associated with inputs
    const adminUrlLabel = page.getByText('Kong Admin URL');
    await expect(adminUrlLabel).toBeVisible();

    const adminUrlInput = page.locator('#admin-url');
    await expect(adminUrlInput).toBeVisible();
    await expect(adminUrlInput).toBeEditable();
  });

  test('should handle keyboard navigation', async ({ page }) => {
    // Tab through interactive elements
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');

    // Check focus is visible
    const focusedElement = await page.evaluate(() =>
      document.activeElement?.tagName
    );
    expect(focusedElement).toBeTruthy();
  });

  test('should display info box with proper styling', async ({ page }) => {
    const infoBox = page.locator('.info-box');
    await expect(infoBox).toBeVisible();

    // Check styling
    const borderColor = await infoBox.evaluate(el =>
      window.getComputedStyle(el).borderLeftColor
    );
    expect(borderColor).toBe('rgb(59, 130, 246)'); // blue border
  });

  test('should handle long response data with scroll', async ({ page }) => {
    // Send multiple requests to generate long response
    for (let i = 0; i < 3; i++) {
      await helpers.clickTestButton('Send Normal Request');
      await page.waitForTimeout(200);
    }

    const responseArea = page.locator('.response-area');
    const overflow = await responseArea.evaluate(el =>
      window.getComputedStyle(el).overflowY
    );
    expect(overflow).toBe('auto');
  });

  test('should maintain result items order', async ({ page }) => {
    // Send different types of requests
    await helpers.clickTestButton('Send Normal Request');
    await page.waitForTimeout(500);
    await helpers.clickTestButton('Test SQL Injection');
    await page.waitForTimeout(500);

    const results = page.locator('.result-item');
    const count = await results.count();
    expect(count).toBeGreaterThan(0);

    // Most recent should be first
    const firstResult = await results.first().textContent();
    expect(firstResult).toContain('SQL Injection');
  });

  test('should display clear button with proper styling', async ({ page }) => {
    const clearBtn = page.getByRole('button', { name: 'Clear Results' });
    await expect(clearBtn).toBeVisible();

    const bgColor = await clearBtn.evaluate(el =>
      window.getComputedStyle(el).backgroundColor
    );
    expect(bgColor).toBe('rgb(108, 117, 125)'); // gray color
  });

  test('should show result items with color-coded borders', async ({ page }) => {
    // Send normal request (success)
    await helpers.clickTestButton('Send Normal Request');
    await page.waitForTimeout(500);

    // Send attack (blocked)
    await helpers.clickTestButton('Test SQL Injection');
    await page.waitForTimeout(500);

    const successResult = page.locator('.result-success').first();
    const blockedResult = page.locator('.result-blocked').first();

    if (await successResult.count() > 0) {
      const successBorder = await successResult.evaluate(el =>
        window.getComputedStyle(el).borderLeftColor
      );
      expect(successBorder).toBe('rgb(40, 167, 69)'); // green
    }

    if (await blockedResult.count() > 0) {
      const blockedBorder = await blockedResult.evaluate(el =>
        window.getComputedStyle(el).borderLeftColor
      );
      expect(blockedBorder).toBe('rgb(255, 193, 7)'); // yellow
    }
  });
});
