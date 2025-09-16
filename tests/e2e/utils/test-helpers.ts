import { Page, expect } from '@playwright/test';

export class DashboardHelpers {
  constructor(private page: Page) {}

  async waitForServicesOnline() {
    // Wait for all services to be checked
    await this.page.waitForTimeout(2000);

    // Check if services are online
    const kongStatus = await this.page.locator('#kong-status').getAttribute('class');
    const adminStatus = await this.page.locator('#admin-status').getAttribute('class');

    if (!kongStatus?.includes('online') || !adminStatus?.includes('online')) {
      console.warn('Some services are not online, waiting...');
      await this.page.waitForTimeout(5000);
    }
  }

  async getResponseData(): Promise<any> {
    const responseText = await this.page.locator('#response').textContent();
    if (!responseText || responseText === 'Response will appear here...') {
      return null;
    }
    try {
      return JSON.parse(responseText);
    } catch {
      return responseText;
    }
  }

  async waitForResponse() {
    // Wait for response area to show - try multiple selectors
    try {
      await this.page.waitForSelector('.response-area.show', { timeout: 10000 });
    } catch {
      // Fallback: check if response has content
      await this.page.waitForFunction(
        () => {
          const response = document.getElementById('response');
          return response && response.textContent !== 'Response will appear here...' && response.textContent !== '';
        },
        { timeout: 10000 }
      );
    }
    await this.page.waitForTimeout(500); // Small delay for content to load
  }

  async checkServiceStatus(serviceName: string): Promise<boolean> {
    const statusId = `#${serviceName}-status`;
    const statusElement = await this.page.locator(statusId);
    const classes = await statusElement.getAttribute('class');
    return classes?.includes('online') || false;
  }

  async clickTestButton(buttonText: string) {
    await this.page.getByRole('button', { name: buttonText }).click();
    await this.waitForResponse();
  }

  async getStatValue(statId: string): Promise<string> {
    return await this.page.locator(`#${statId}`).textContent() || '';
  }

  async checkThreatBlocked(threatType: string): Promise<boolean> {
    const response = await this.getResponseData();
    return response?.blocked === true && response?.threat === threatType;
  }

  async checkRequestAllowed(): Promise<boolean> {
    const response = await this.getResponseData();
    return response?.status === 200 && response?.action === 'Allowed';
  }

  async getPluginState(): Promise<string> {
    return await this.page.locator('#plugin-state').textContent() || '';
  }

  async updateConfiguration(field: 'admin-url' | 'proxy-url' | 'api-path', value: string) {
    await this.page.locator(`#${field}`).fill(value);
  }
}
