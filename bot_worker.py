import os
import asyncio
import discord
from discord import app_commands
from typing import Optional

from license_core import (
    db_init, db_create_license, db_find_license_row, db_set_revoked,
    db_delete_license, db_add_time, db_reset_hwid, now_ts, fmt_ts, normalize_key
)

TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
GUILD_ID = int(os.environ.get("GUILD_ID", "0"))
LICENSE_ADMIN_ROLE_ID = int(os.environ.get("LICENSE_ADMIN_ROLE_ID", "0"))

if not TOKEN:
    raise SystemExit("Missing DISCORD_BOT_TOKEN env var.")
if GUILD_ID == 0 or LICENSE_ADMIN_ROLE_ID == 0:
    raise SystemExit("Missing GUILD_ID or LICENSE_ADMIN_ROLE_ID env var.")

def require_admin(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        return False
    if interaction.guild.id != GUILD_ID:
        return False
    if not isinstance(interaction.user, discord.Member):
        return False
    return any(r.id == LICENSE_ADMIN_ROLE_ID for r in interaction.user.roles)

async def deny(interaction: discord.Interaction):
    return await interaction.response.send_message(
        "❌ Not allowed. (Admin role required, and command must be used in the server.)",
        ephemeral=True
    )

DURATION_SECONDS = {
    "1d": 1 * 24 * 3600,
    "3d": 3 * 24 * 3600,
    "1w": 7 * 24 * 3600,
    "1m": 30 * 24 * 3600,
    "lifetime": None
}

DURATION_CHOICES = [
    app_commands.Choice(name="1 day", value="1d"),
    app_commands.Choice(name="3 days", value="3d"),
    app_commands.Choice(name="1 week", value="1w"),
    app_commands.Choice(name="1 month (30d)", value="1m"),
    app_commands.Choice(name="lifetime", value="lifetime"),
]

class Bot(discord.Client):
    def __init__(self):
        super().__init__(intents=discord.Intents.default())
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        await db_init()
        guild_obj = discord.Object(id=GUILD_ID)
        self.tree.copy_global_to(guild=guild_obj)
        await self.tree.sync(guild=guild_obj)
        print("Synced commands to guild.")

bot = Bot()

@bot.event
async def on_ready():
    print(f"Bot online as {bot.user} ({bot.user.id})")

@bot.tree.command(name="lic_gen", description="(Admin) Generate a license key")
@app_commands.choices(duration=DURATION_CHOICES)
async def lic_gen(interaction: discord.Interaction, duration: app_commands.Choice[str]):
    if not require_admin(interaction):
        return await deny(interaction)

    seconds = DURATION_SECONDS[duration.value]
    exp = None if seconds is None else now_ts() + int(seconds)

    key = await db_create_license(expires_at=exp, created_by=interaction.user.id)
    await interaction.response.send_message(
        "\n".join([
            "✅ **License generated**",
            f"Key: `{key}`",
            f"Expires: {fmt_ts(exp)}",
        ]),
        ephemeral=True
    )

@bot.tree.command(name="lic_info", description="(Admin) Show license status")
@app_commands.describe(license_key="The license key")
async def lic_info(interaction: discord.Interaction, license_key: str):
    if not require_admin(interaction):
        return await deny(interaction)

    license_key = normalize_key(license_key)
    row = await db_find_license_row(license_key)
    if not row:
        return await interaction.response.send_message("Not found.", ephemeral=True)

    lic_id, created_at, created_by, expires_at, revoked, hwid_hash, last_seen_at = row

    await interaction.response.send_message(
        "\n".join([
            f"🔎 **License info** `{license_key}`",
            f"ID: `{lic_id}`",
            f"Created by: `<@{created_by}>`",
            f"Expires: {fmt_ts(expires_at)}",
            f"Revoked: `{bool(revoked)}`",
            f"HWID bound: `{hwid_hash is not None}`",
            f"Last seen: {fmt_ts(last_seen_at) if last_seen_at else 'never'}",
        ]),
        ephemeral=True
    )

@bot.tree.command(name="lic_revoke", description="(Admin) Revoke a license")
@app_commands.describe(license_key="The license key")
async def lic_revoke(interaction: discord.Interaction, license_key: str):
    if not require_admin(interaction):
        return await deny(interaction)
    ok = await db_set_revoked(normalize_key(license_key), True)
    await interaction.response.send_message("✅ Revoked." if ok else "Not found.", ephemeral=True)

@bot.tree.command(name="lic_unrevoke", description="(Admin) Unrevoke a license")
@app_commands.describe(license_key="The license key")
async def lic_unrevoke(interaction: discord.Interaction, license_key: str):
    if not require_admin(interaction):
        return await deny(interaction)
    ok = await db_set_revoked(normalize_key(license_key), False)
    await interaction.response.send_message("✅ Unrevoked." if ok else "Not found.", ephemeral=True)

@bot.tree.command(name="lic_delete", description="(Admin) DELETE a license (permanent)")
@app_commands.describe(license_key="The license key")
async def lic_delete(interaction: discord.Interaction, license_key: str):
    if not require_admin(interaction):
        return await deny(interaction)
    ok = await db_delete_license(normalize_key(license_key))
    await interaction.response.send_message("✅ Deleted." if ok else "Not found.", ephemeral=True)

@bot.tree.command(name="lic_addtime", description="(Admin) Add time to a license")
@app_commands.describe(license_key="The license key", days="Days to add (e.g. 7)")
async def lic_addtime(interaction: discord.Interaction, license_key: str, days: int):
    if not require_admin(interaction):
        return await deny(interaction)
    if days <= 0 or days > 3650:
        return await interaction.response.send_message("Invalid days.", ephemeral=True)

    ok, info = await db_add_time(normalize_key(license_key), days * 24 * 3600)
    if not ok:
        return await interaction.response.send_message("Not found.", ephemeral=True)
    if info == "lifetime_noop":
        return await interaction.response.send_message("Lifetime; addtime is a no-op.", ephemeral=True)

    await interaction.response.send_message(f"✅ Added time. New expires_at: {fmt_ts(int(info))}", ephemeral=True)

@bot.tree.command(name="lic_reset_hwid", description="(Admin) Unbind HWID so it can activate on a new PC")
@app_commands.describe(license_key="The license key")
async def lic_reset_hwid(interaction: discord.Interaction, license_key: str):
    if not require_admin(interaction):
        return await deny(interaction)
    ok = await db_reset_hwid(normalize_key(license_key))
    await interaction.response.send_message("✅ HWID reset." if ok else "Not found.", ephemeral=True)

async def start_bot():
    await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(start_bot())
