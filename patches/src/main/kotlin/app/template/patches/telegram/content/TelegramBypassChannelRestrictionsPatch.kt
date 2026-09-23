package app.template.patches.telegram.content

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.extensions.InstructionExtensions.getInstruction
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.fieldAccess
import app.morphe.patcher.patch.bytecodePatch
import app.template.patches.shared.Constants.TELEGRAM_COMPATIBILITY
import app.template.patches.telegram.CheckChannelErrorFingerprint
import app.template.patches.telegram.CheckSensitiveFingerprint
import app.template.patches.telegram.GetChannelDiffErrorFingerprint
import app.template.patches.telegram.CreateNoAccessAlertFingerprint
import app.template.patches.telegram.GetRestrictionReasonFingerprint
import app.template.patches.telegram.LoadFullChatErrorFingerprint
import app.template.patches.telegram.MessageObjectIsHiddenSensitiveFingerprint
import app.template.patches.telegram.ChatActivityHasSelectedNoforwardsMessageFingerprint
import app.template.patches.telegram.CanForwardMessageFingerprint
import app.template.patches.telegram.MessageObjectNeedDrawShareButtonFingerprint
import app.template.patches.telegram.PhotoViewerC2Fingerprint
import app.template.patches.telegram.PhotoViewerG2Fingerprint
import app.template.patches.telegram.MessagesControllerIsChatNoForwardsLongFingerprint
import app.template.patches.telegram.MessagesControllerIsChatNoForwardsChatFingerprint
import app.template.patches.telegram.MessagesControllerIsPeerNoForwardsFingerprint
import app.template.patches.telegram.MessagesControllerIsUserNoForwardsLongFingerprint
import app.template.patches.telegram.MessagesControllerIsUserNoForwardsUserFullFingerprint
import app.template.patches.telegram.ChatActivityIsPeerNoForwardsFingerprint
import app.template.patches.telegram.ProfileActivityIsPeerNoForwardsFingerprint
import app.template.patches.telegram.MessageObjectIsSensitiveFingerprint
import app.template.patches.telegram.MessageObjectUpdateMessageTextFingerprint
import app.template.patches.telegram.MessagesControllerIsSensitiveFingerprint
import app.template.patches.telegram.SetContentSettingsFingerprint
import app.template.patches.telegram.ShowCantOpenAlertFingerprint
import app.template.patches.telegram.ShowSensitiveContentFingerprint
import app.template.patches.telegram.signature.telegramSpoofDependency
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.FieldReference

@Suppress("unused")
val telegramBypassChannelRestrictionsPatch = bytecodePatch(
    name = "Bypass channel restrictions",
    description = "Allows opening, viewing, saving and forwarding content from restricted, " +
        "sensitive, and copyright-restricted channels.",
) {
    compatibleWith(TELEGRAM_COMPATIBILITY)
    dependsOn(telegramSpoofDependency())

    execute {

        // ── Layer 1: null the source ──────────────────────────────────────────
        // getRestrictionReason(ArrayList) → null
        // Covers all call sites inside MessageObject and PhotoViewer.
        GetRestrictionReasonFingerprint.method.addInstructions(0, """
            const/4 v0, 0x0
            return-object v0
        """)

        // ── Layer 2: block updateMessageText entirely ─────────────────────────
        // Prevents messageText and isRestrictedMessage from ever being overwritten.
        MessageObjectUpdateMessageTextFingerprint.method.addInstructions(0, "return-void")

        // ── Layer 4: replace all isRestrictedMessage READS → false ───────────
        Fingerprint(filters = listOf(fieldAccess(
            opcode = Opcode.IGET_BOOLEAN,
            definingClass = "Lorg/telegram/messenger/MessageObject;",
            name = "isRestrictedMessage",
            type = "Z",
        ))).matchAllOrNull()?.forEach { match ->
            match.method.apply {
                match.instructionMatches.map { it.index }.reversed().forEach { idx ->
                    val reg = getInstruction<TwoRegisterInstruction>(idx).registerA
                    replaceInstruction(idx, "const/4 v$reg, 0x0")
                }
            }
        }

        // ── Layer 5: replace all isRestrictedMessage WRITES → false ──────────
        Fingerprint(filters = listOf(fieldAccess(
            opcode = Opcode.IPUT_BOOLEAN,
            definingClass = "Lorg/telegram/messenger/MessageObject;",
            name = "isRestrictedMessage",
            type = "Z",
        ))).matchAllOrNull()?.forEach { match ->
            match.method.apply {
                match.instructionMatches.map { it.index }.reversed().forEach { idx ->
                    val reg = getInstruction<TwoRegisterInstruction>(idx).registerA
                    replaceInstruction(idx, "const/4 v$reg, 0x0")
                }
            }
        }

        // ── Peer-level no-forwards ───────────────────────────────────────────
        // Disable chat/user-level forwarding policy gates as well.
        listOf(
            MessagesControllerIsChatNoForwardsLongFingerprint,
            MessagesControllerIsChatNoForwardsChatFingerprint,
            MessagesControllerIsPeerNoForwardsFingerprint,
            MessagesControllerIsUserNoForwardsLongFingerprint,
            MessagesControllerIsUserNoForwardsUserFullFingerprint,
            ChatActivityIsPeerNoForwardsFingerprint,
            ProfileActivityIsPeerNoForwardsFingerprint,
        ).forEach { fingerprint ->
            fingerprint.methodOrNull?.addInstructions(0, """
                const/4 v0, 0x0
                return v0
            """)
        }

        // Bypass the share-button gate that directly checks Message.noforwards.
        MessageObjectNeedDrawShareButtonFingerprint.method.implementation!!.instructions
            .withIndex()
            .first { (_, instruction) ->
                val ref = (instruction as? ReferenceInstruction)?.reference as? FieldReference
                ref?.definingClass == "Lorg/telegram/tgnet/TLRPC\$Message;" &&
                    ref.name == "noforwards" &&
                    instruction.opcode.name == "IGET_BOOLEAN"
            }.let { match ->
                val reg = getInstruction<TwoRegisterInstruction>(match.index).registerA
                MessageObjectNeedDrawShareButtonFingerprint.method.replaceInstruction(
                    match.index,
                    "const/4 v$reg, 0x0",
                )
            }

        // Bypass the PhotoViewer media-action gate that directly checks Message.noforwards.
        PhotoViewerG2Fingerprint.method.implementation!!.instructions
            .withIndex()
            .first { (_, instruction) ->
                val ref = (instruction as? ReferenceInstruction)?.reference as? FieldReference
                ref?.definingClass == "Lorg/telegram/tgnet/TLRPC\$Message;" &&
                    ref.name == "noforwards" &&
                    instruction.opcode.name == "IGET_BOOLEAN"
            }.let { match ->
                val reg = getInstruction<TwoRegisterInstruction>(match.index).registerA
                PhotoViewerG2Fingerprint.method.replaceInstruction(
                    match.index,
                    "const/4 v$reg, 0x0",
                )
            }

        // ── No-forwards ───────────────────────────────────────────────────────
        // Telegram gates forwarding of selected messages through po.Z8(), which
        // returns true when any selected MessageObject has messageOwner.noforwards.
        ChatActivityHasSelectedNoforwardsMessageFingerprint.method.addInstructions(0, """
            const/4 v0, 0x0
            return v0
        """)

        // Remove only the per-message noforwards gate; preserve other forwarding restrictions.
        val noForwardsCheck = CanForwardMessageFingerprint.method.implementation!!.instructions
            .withIndex()
            .first { (_, instruction) ->
                val ref = (instruction as? ReferenceInstruction)?.reference as? FieldReference
                ref?.definingClass == "Lorg/telegram/tgnet/TLRPC\$Message;" &&
                    ref.name == "noforwards" &&
                    instruction.opcode.name == "IGET_BOOLEAN"
            }
        CanForwardMessageFingerprint.method.replaceInstruction(noForwardsCheck.index, "nop")

        // ── Sensitive content ─────────────────────────────────────────────────
        SetContentSettingsFingerprint.method.addInstructions(0, "const/4 p1, 0x1")
        ShowSensitiveContentFingerprint.method.addInstructions(0, """
            const/4 v0, 0x1
            return v0
        """)
        MessagesControllerIsSensitiveFingerprint.method.addInstructions(0, """
            const/4 v0, 0x0
            return v0
        """)
        CheckSensitiveFingerprint.method.addInstructions(0, """
            if-eqz p4, :skip
            invoke-interface {p4}, Ljava/lang/Runnable;->run()V
            :skip
            return-void
        """)
        MessageObjectIsSensitiveFingerprint.method.addInstructions(0, """
            const/4 v0, 0x0
            return v0
        """)
        MessageObjectIsHiddenSensitiveFingerprint.method.addInstructions(0, """
            const/4 v0, 0x0
            return v0
        """)

        // ── Channel access errors ─────────────────────────────────────────────
        ShowCantOpenAlertFingerprint.method.addInstructions(0, "return-void")
        CheckChannelErrorFingerprint.method.addInstructions(0, "return-void")
        mutableClassDefBy("Lorg/telegram/ui/Components/d5;").methods.single {
            it.name == "F" &&
                it.returnType == "Lorg/telegram/ui/ActionBar/AlertDialog\$Builder;" &&
                it.parameterTypes == listOf(
                    "Landroid/content/Context;",
                    "Ljava/lang/String;",
                    "Ljava/lang/String;",
                )
        }.addInstructions(0, """
            const/4 v0, 0x0
            return-object v0
        """)
        LoadFullChatErrorFingerprint.method.addInstructions(0, "return-void")
        GetChannelDiffErrorFingerprint.methodOrNull?.addInstructions(0, "return-void")

        // ── Chat open permission ──────────────────────────────────────────────
        // R8 changes the parameter descriptors of checkCanOpenChat across Telegram
        // builds. Resolve the mutable class directly instead of relying on three
        // fragile fingerprints.
        val checkCanOpenChatMethods = mutableClassDefBy("Lorg/telegram/messenger/MessagesController;").methods
            .filter {
                it.name == "checkCanOpenChat" &&
                    it.returnType == "Z"
            }

        check(checkCanOpenChatMethods.size == 1) {
            "Expected exactly 1 MessagesController.checkCanOpenChat(Z-returning) method, " +
                "found ${checkCanOpenChatMethods.size}"
        }

        checkCanOpenChatMethods.single().addInstructions(0, """
            const/4 v0, 0x1
            return v0
        """)
    }
}
