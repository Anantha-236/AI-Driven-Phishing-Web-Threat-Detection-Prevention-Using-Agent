const { chromium } = require("playwright");

(async () => {
	const browser = await chromium.launch({ channel: "chromium", headless: true });
	console.log(`PLAYWRIGHT_CHROMIUM_VERSION=${browser.version()}`);
	await browser.close();
})();
