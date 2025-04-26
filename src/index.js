import axios from "axios";
import schedule from "node-schedule";

const HETZNER_API_TOKEN = process.env.HETZNER_API_TOKEN;
const HETZNER_FIREWALL_ID = process.env.HETZNER_FIREWALL_ID;
if (!HETZNER_API_TOKEN || !HETZNER_FIREWALL_ID) {
  throw new Error("HETZNER_API_TOKEN and HETZNER_FIREWALL_ID must be set");
}

async function getCloudflareIps() {
  try {
    const response = await axios.get("https://www.cloudflare.com/ips-v4");
    return response.data.split("\n").map(ip => ip.trim());
  } catch (error) {
    console.error("Failed to fetch Cloudflare IPs", error);
    return [];
  }
}

async function whitelistCloudflareIps(ipRanges) {
  const data = {
    rules: [
      {
        direction: "in",
        source_ips: ipRanges,
        port: "443",
        protocol: "tcp",
        description: "Accept port 443",
      },
      {
        direction: "in",
        source_ips: ipRanges,
        port: "80",
        protocol: "tcp",
        description: "Accept port 80",
      },
    ]
  }

  try {
    const response = await axios.post(`https://api.hetzner.cloud/v1/firewalls/${HETZNER_FIREWALL_ID}/actions/set_rules`, data, {
      headers: {
        "Authorization": `Bearer ${HETZNER_API_TOKEN}`,
        "Content-Type": "application/json",
      }
    });

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Failed to whitelist Cloudflare IPs: ${response.statusText}`);
    }

    console.log("Successfully whitelisted Cloudflare IPs");
  } catch (error) {
    console.error("Error whitelisting Cloudflare IPs", error);
  }
}

async function update() {
  const ipRanges = await getCloudflareIps();
  await whitelistCloudflareIps(ipRanges);
}

update();
schedule.scheduleJob("0 0 * * *", update);
