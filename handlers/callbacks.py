"""
handlers/callbacks.py - InlineKeyboard callback query handler.
Handles old callbacks cleanly if clicked by the user.
"""
from telegram import Update
from telegram.ext import ContextTypes

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query:
        try:
            await query.answer("This option is no longer available.", show_alert=True)
        except Exception:
            pass
