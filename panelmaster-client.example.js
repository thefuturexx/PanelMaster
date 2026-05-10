const { PanelMasterClient } = require("./panelmaster-client");

async function main() {
  const client = new PanelMasterClient({
    baseUrl: "http://YOUR_PANEL_IP:8888",
    apiKey: "My_Super_Secret_VPN_Key_2026"
  });

  // 1) list active groups
  const groups = await client.getActiveGroups();
  console.log("groups:", groups);

  // 2) create user key in group
  const created = await client.createUser({
    masterGroupId: "group_01",
    userName: "demo_user_001",
    totalGB: 50,
    expireDate: "2026-12-31"
  });
  console.log("created:", created);

  const token = created?.token;
  if (!token) return;

  // 3) switch active server for user
  await client.switchServer({
    token,
    activeServer: "auto_02"
  });
  console.log("switched");

  // 4) read user config json
  const conf = await client.getUserConfig(token);
  console.log("conf:", conf);

  // 5) suspend / resume / delete example
  await client.suspendUser(token);
  console.log("suspended");

  await client.resumeUser(token);
  console.log("resumed");

  // await client.deleteUser(token);
  // console.log("deleted");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

