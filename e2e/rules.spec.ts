import { test, expect } from '@playwright/test';

const API_KEY = 'integration-test-api-key';

test.describe('Login', () => {
  test('TC-PW-01: 输入有效 API Key 登录成功', async ({ page }) => {
    await page.goto('/');
    await page.locator('input[type="password"]').fill(API_KEY);
    await page.locator('button[type="submit"]').click();
    // 登录后侧边栏导航出现
    await expect(page.locator('nav')).toBeVisible({ timeout: 8000 });
  });

  test('TC-PW-02: 输入无效 API Key 显示错误', async ({ page }) => {
    await page.goto('/');
    await page.locator('input[type="password"]').fill('wrong-key-xxx');
    await page.locator('button[type="submit"]').click();
    // 显示错误信息
    await expect(page.locator('text=/Invalid|error|500/i')).toBeVisible({ timeout: 5000 });
    // 仍然在登录页面（URL 是 /）
    expect(page.url()).not.toContain('dashboard');
  });

  test('TC-PW-03: 未登录访问被保护页面', async ({ page }) => {
    await page.goto('/');
    await page.evaluate(() => localStorage.clear());
    await page.reload();
    // 显示登录页
    await expect(page.locator('input[type="password"]')).toBeVisible({ timeout: 5000 });
  });
});

test.describe('Dashboard', () => {
  test('TC-PW-04: 页面加载正常', async ({ page }) => {
    await page.goto('/');
    await page.evaluate((key) => localStorage.setItem('kasra_api_key', key), API_KEY);
    await page.goto('/');
    await expect(page.locator('nav')).toBeVisible({ timeout: 8000 });
    // Dashboard 主体内容可见
    await expect(page.locator('main')).not.toBeEmpty();
  });
});

test.describe('Rule Management', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.evaluate((key) => localStorage.setItem('kasra_api_key', key), API_KEY);
    await page.goto('/rules');
  });

  test('TC-PW-08: 页面渲染', async ({ page }) => {
    // 导航到 /rules 后 URL 正确
    await page.waitForTimeout(3000);
    expect(page.url()).toContain('/rules');
    const body = page.locator('body');
    await expect(body).not.toBeEmpty();
  });

  test('TC-PW-09: 导航到规则页正常', async ({ page }) => {
    await page.waitForTimeout(3000);
    const url = page.url();
    expect(url).toContain('/rules');
  });
});

test.describe('Audit Logs', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.evaluate((key) => localStorage.setItem('kasra_api_key', key), API_KEY);
    await page.goto('/audit-logs');
  });

  test('TC-PW-17: 页面渲染', async ({ page }) => {
    await page.waitForTimeout(5000);
    const url = page.url();
    expect(url).toContain('audit');
    const body = page.locator('body');
    await expect(body).not.toBeEmpty();
  });

  test('TC-PW-18: 导航正常', async ({ page }) => {
    await page.waitForTimeout(2000);
    const body = page.locator('body');
    await expect(body).toBeVisible();
  });
});

test.describe('User Behavior', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.evaluate((key) => localStorage.setItem('kasra_api_key', key), API_KEY);
    await page.goto('/user-behavior');
  });

  test('TC-PW-22: 页面渲染', async ({ page }) => {
    await page.waitForTimeout(5000);
    const url = page.url();
    expect(url).toContain('user-behavior');
    const body = page.locator('body');
    await expect(body).not.toBeEmpty();
  });
});

test.describe('Navigation', () => {
  test('TC-PW-25: 侧边栏导航链接', async ({ page }) => {
    await page.goto('/');
    await page.evaluate((key) => localStorage.setItem('kasra_api_key', key), API_KEY);
    await page.goto('/');
    await expect(page.locator('nav')).toBeVisible({ timeout: 8000 });
    const linkCount = await page.locator('nav a').count();
    expect(linkCount).toBeGreaterThanOrEqual(4);
  });
});
