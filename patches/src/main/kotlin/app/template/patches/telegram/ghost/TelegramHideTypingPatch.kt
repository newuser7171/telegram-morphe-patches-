package app.template.patches.telegram.ghost

import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.template.patches.shared.Constants.TELEGRAM_COMPATIBILITY
import app.template.patches.shared.Constants.TELEGRAM_PLUS_COMPATIBILITY
import app.template.patches.shared.Constants.TELEGRAM_WEB_COMPATIBILITY
import app.template.patches.telegram.signature.telegramSpoofDependency
import app.template.patches.telegram.PlusSendTypingFingerprint

@Suppress("unused")
val telegramHideTypingPatch = bytecodePatch(
    name = "Hide typing indicator",
    description = "Prevents Telegram's typing dispatcher from sending typing notifications.",
) {
    compatibleWith(TELEGRAM_COMPATIBILITY, TELEGRAM_WEB_COMPATIBILITY, TELEGRAM_PLUS_COMPATIBILITY)
    dependsOn(telegramSpoofDependency())

    execute {
        // Telegram 12.10.3 (70892): the UI typing callback dispatches through
        // MessagesController.sendTyping(JJII)Z. Returning false here prevents
        // that request from being sent and avoids relying on R8-renamed
        // needSendTyping() callback implementations.
        check(PlusSendTypingFingerprint.method.implementation != null) {
            "Expected concrete MessagesController.sendTyping(JJII)Z for Telegram 12.10.3"
        }
        PlusSendTypingFingerprint.method.addInstructions(0, """
            const/4 v0, 0x0
            return v0
        """)
    }
}
