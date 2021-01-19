/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2021 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Text;

#if !KeePassUAP
using System.Windows.Forms;
#endif

using KeePassLib.Resources;
using KeePassLib.Serialization;

namespace KeePassLib.Utility
{
    public sealed class MessageServiceEventArgs : EventArgs
    {
        private readonly string m_strTitle = string.Empty;
        private readonly string m_strText = string.Empty;
        private readonly MessageBoxButtons m_msgButtons = MessageBoxButtons.OK;
        private readonly MessageBoxIcon m_msgIcon = MessageBoxIcon.None;

        public string Title => m_strTitle;
        public string Text => m_strText;
        public MessageBoxButtons Buttons => m_msgButtons;
        public MessageBoxIcon Icon => m_msgIcon;

        public MessageServiceEventArgs() { }

        public MessageServiceEventArgs(string strTitle, string strText,
            MessageBoxButtons msgButtons, MessageBoxIcon msgIcon)
        {
            m_strTitle = (strTitle ?? string.Empty);
            m_strText = (strText ?? string.Empty);
            m_msgButtons = msgButtons;
            m_msgIcon = msgIcon;
        }
    }

    public static class MessageService
    {
        private static volatile uint m_uCurrentMessageCount = 0;

#if !KeePassLibSD
        private const MessageBoxIcon m_mbiInfo = MessageBoxIcon.Information;
        private const MessageBoxIcon m_mbiWarning = MessageBoxIcon.Warning;
        private const MessageBoxIcon m_mbiFatal = MessageBoxIcon.Error;

        private const MessageBoxOptions m_mboRtl = (MessageBoxOptions.RtlReading |
            MessageBoxOptions.RightAlign);
#else
		private const MessageBoxIcon m_mbiInfo = MessageBoxIcon.Asterisk;
		private const MessageBoxIcon m_mbiWarning = MessageBoxIcon.Exclamation;
		private const MessageBoxIcon m_mbiFatal = MessageBoxIcon.Hand;
#endif
        private const MessageBoxIcon m_mbiQuestion = MessageBoxIcon.Question;

        public static string NewLine => Environment.NewLine;

        public static string NewParagraph => Environment.NewLine + Environment.NewLine;

        public static uint CurrentMessageCount => m_uCurrentMessageCount;

#if !KeePassUAP
        public static event EventHandler<MessageServiceEventArgs> MessageShowing;
#endif

        private static string ObjectsToMessage(object[] vLines) => ObjectsToMessage(vLines, false);

        private static string ObjectsToMessage(object[] vLines, bool bFullExceptions)
        {
            if (vLines == null) return string.Empty;

            var strNewPara = MessageService.NewParagraph;

            var sbText = new StringBuilder();
            var bSeparator = false;

            foreach (var obj in vLines)
            {
                if (obj == null) continue;

                string strAppend = null;

                var exObj = (obj as Exception);
                var strObj = (obj as string);
#if !KeePassLibSD
                var scObj = (obj as StringCollection);
#endif

                if (exObj != null)
                {
                    if (bFullExceptions)
                        strAppend = StrUtil.FormatException(exObj);
                    else if (!string.IsNullOrEmpty(exObj.Message))
                        strAppend = exObj.Message;
                }
#if !KeePassLibSD
                else if (scObj != null)
                {
                    var sb = new StringBuilder();
                    foreach (var strCollLine in scObj)
                    {
                        if (sb.Length > 0) sb.AppendLine();
                        sb.Append(strCollLine.TrimEnd());
                    }
                    strAppend = sb.ToString();
                }
#endif
                else if (strObj != null)
                    strAppend = strObj;
                else
                    strAppend = obj.ToString();

                if (!string.IsNullOrEmpty(strAppend))
                {
                    if (bSeparator) sbText.Append(strNewPara);
                    else bSeparator = true;

                    sbText.Append(strAppend);
                }
            }

            return sbText.ToString();
        }

#if (!KeePassLibSD && !KeePassUAP)
        internal static Form GetTopForm()
        {
            FormCollection fc = Application.OpenForms;
            if ((fc == null) || (fc.Count == 0)) return null;

            return fc[fc.Count - 1];
        }
#endif

#if !KeePassUAP
        internal static DialogResult SafeShowMessageBox(string strText, string strTitle,
            MessageBoxButtons mb, MessageBoxIcon mi, MessageBoxDefaultButton mdb)
        {
            // strText += MessageService.NewParagraph + (new StackTrace(true)).ToString();

#if KeePassLibSD
			return MessageBox.Show(strText, strTitle, mb, mi, mdb);
#else
            IWin32Window wnd = null;
            try
            {
                Form f = GetTopForm();
                if ((f != null) && f.InvokeRequired)
                    return (DialogResult)f.Invoke(new SafeShowMessageBoxInternalDelegate(
                        SafeShowMessageBoxInternal), f, strText, strTitle, mb, mi, mdb);
                else wnd = f;
            }
            catch (Exception) { Debug.Assert(false); }

            if (wnd == null)
            {
                if (StrUtil.RightToLeft)
                    return MessageBox.Show(strText, strTitle, mb, mi, mdb, m_mboRtl);
                return MessageBox.Show(strText, strTitle, mb, mi, mdb);
            }

            try
            {
                if (StrUtil.RightToLeft)
                    return MessageBox.Show(wnd, strText, strTitle, mb, mi, mdb, m_mboRtl);
                return MessageBox.Show(wnd, strText, strTitle, mb, mi, mdb);
            }
            catch (Exception) { Debug.Assert(false); }

            if (StrUtil.RightToLeft)
                return MessageBox.Show(strText, strTitle, mb, mi, mdb, m_mboRtl);
            return MessageBox.Show(strText, strTitle, mb, mi, mdb);
#endif
        }

#if !KeePassLibSD
        internal delegate DialogResult SafeShowMessageBoxInternalDelegate(IWin32Window iParent,
            string strText, string strTitle, MessageBoxButtons mb, MessageBoxIcon mi,
            MessageBoxDefaultButton mdb);

        internal static DialogResult SafeShowMessageBoxInternal(IWin32Window iParent,
            string strText, string strTitle, MessageBoxButtons mb, MessageBoxIcon mi,
            MessageBoxDefaultButton mdb)
        {
            if (StrUtil.RightToLeft)
                return MessageBox.Show(iParent, strText, strTitle, mb, mi, mdb, m_mboRtl);
            return MessageBox.Show(iParent, strText, strTitle, mb, mi, mdb);
        }
#endif

        public static void ShowInfo(params object[] vLines) => ShowInfoEx(null, vLines);

        public static void ShowInfoEx(string strTitle, params object[] vLines)
        {
            ++m_uCurrentMessageCount;

            strTitle = (strTitle ?? PwDefs.ShortProductName);
            var strText = ObjectsToMessage(vLines);

            if (MessageService.MessageShowing != null)
                MessageService.MessageShowing(null, new MessageServiceEventArgs(
                    strTitle, strText, MessageBoxButtons.OK, m_mbiInfo));

            SafeShowMessageBox(strText, strTitle, MessageBoxButtons.OK, m_mbiInfo,
                MessageBoxDefaultButton.Button1);

            --m_uCurrentMessageCount;
        }

        public static void ShowWarning(params object[] vLines) => ShowWarningPriv(vLines, false);

        internal static void ShowWarningExcp(params object[] vLines) => ShowWarningPriv(vLines, true);

        private static void ShowWarningPriv(object[] vLines, bool bFullExceptions)
        {
            ++m_uCurrentMessageCount;

            var strTitle = PwDefs.ShortProductName;
            var strText = ObjectsToMessage(vLines, bFullExceptions);

            if (MessageService.MessageShowing != null)
                MessageService.MessageShowing(null, new MessageServiceEventArgs(
                    strTitle, strText, MessageBoxButtons.OK, m_mbiWarning));

            SafeShowMessageBox(strText, strTitle, MessageBoxButtons.OK, m_mbiWarning,
                MessageBoxDefaultButton.Button1);

            --m_uCurrentMessageCount;
        }

        public static void ShowFatal(params object[] vLines)
        {
            ++m_uCurrentMessageCount;

            var strTitle = PwDefs.ShortProductName + " - " + KLRes.FatalError;
            var strText = KLRes.FatalErrorText + MessageService.NewParagraph +
                KLRes.ErrorInClipboard + MessageService.NewParagraph +
                // Please send it to the KeePass developers.
                // KLRes.ErrorFeedbackRequest + MessageService.NewParagraph +
                ObjectsToMessage(vLines);

            try
            {
                var strDetails = ObjectsToMessage(vLines, true);

#if KeePassLibSD
				Clipboard.SetDataObject(strDetails);
#else
                Clipboard.Clear();
                Clipboard.SetText(strDetails);
#endif
            }
            catch (Exception) { Debug.Assert(false); }

            if (MessageService.MessageShowing != null)
                MessageService.MessageShowing(null, new MessageServiceEventArgs(
                    strTitle, strText, MessageBoxButtons.OK, m_mbiFatal));

            SafeShowMessageBox(strText, strTitle, MessageBoxButtons.OK, m_mbiFatal,
                MessageBoxDefaultButton.Button1);

            --m_uCurrentMessageCount;
        }

        public static DialogResult Ask(string strText, string strTitle,
            MessageBoxButtons mbb)
        {
            ++m_uCurrentMessageCount;

            var strTextEx = (strText ?? string.Empty);
            var strTitleEx = (strTitle ?? PwDefs.ShortProductName);

            if (MessageService.MessageShowing != null)
                MessageService.MessageShowing(null, new MessageServiceEventArgs(
                    strTitleEx, strTextEx, mbb, m_mbiQuestion));

            DialogResult dr = SafeShowMessageBox(strTextEx, strTitleEx, mbb,
                m_mbiQuestion, MessageBoxDefaultButton.Button1);

            --m_uCurrentMessageCount;
            return dr;
        }

        public static bool AskYesNo(string strText, string strTitle, bool bDefaultToYes,
            MessageBoxIcon mbi)
        {
            ++m_uCurrentMessageCount;

            var strTextEx = (strText ?? string.Empty);
            var strTitleEx = (strTitle ?? PwDefs.ShortProductName);

            if (MessageService.MessageShowing != null)
                MessageService.MessageShowing(null, new MessageServiceEventArgs(
                    strTitleEx, strTextEx, MessageBoxButtons.YesNo, mbi));

            DialogResult dr = SafeShowMessageBox(strTextEx, strTitleEx,
                MessageBoxButtons.YesNo, mbi, bDefaultToYes ?
                MessageBoxDefaultButton.Button1 : MessageBoxDefaultButton.Button2);

            --m_uCurrentMessageCount;
            return (dr == DialogResult.Yes);
        }

        public static bool AskYesNo(string strText, string strTitle, bool bDefaultToYes) => AskYesNo(strText, strTitle, bDefaultToYes, m_mbiQuestion);

        public static bool AskYesNo(string strText, string strTitle) => AskYesNo(strText, strTitle, true, m_mbiQuestion);

        public static bool AskYesNo(string strText) => AskYesNo(strText, null, true, m_mbiQuestion);

        public static void ShowLoadWarning(string strFilePath, Exception ex) => ShowLoadWarning(strFilePath, ex, false);

        public static void ShowLoadWarning(string strFilePath, Exception ex,
            bool bFullException) => ShowWarning(GetLoadWarningMessage(strFilePath, ex, bFullException));

        public static void ShowLoadWarning(IOConnectionInfo ioConnection, Exception ex)
        {
            if (ioConnection != null)
                ShowLoadWarning(ioConnection.GetDisplayName(), ex, false);
            else ShowWarning(ex);
        }

        public static void ShowSaveWarning(string strFilePath, Exception ex,
            bool bCorruptionWarning)
        {
            var fl = (ex as FileLockException);
            if (fl != null)
            {
                ShowWarning(fl.Message);
                return;
            }

            var str = GetSaveWarningMessage(strFilePath, ex, bCorruptionWarning);
            ShowWarning(str);
        }

        public static void ShowSaveWarning(IOConnectionInfo ioConnection, Exception ex,
            bool bCorruptionWarning)
        {
            if (ioConnection != null)
                ShowSaveWarning(ioConnection.GetDisplayName(), ex, bCorruptionWarning);
            else ShowWarning(ex);
        }
#endif // !KeePassUAP

        internal static string GetLoadWarningMessage(string strFilePath,
            Exception ex, bool bFullException)
        {
            var str = string.Empty;

            if (!string.IsNullOrEmpty(strFilePath))
                str += strFilePath + MessageService.NewParagraph;

            str += KLRes.FileLoadFailed;

            if ((ex != null) && !string.IsNullOrEmpty(ex.Message))
            {
                str += MessageService.NewParagraph;
                if (!bFullException) str += ex.Message;
                else str += ObjectsToMessage(new object[] { ex }, true);
            }

            return str;
        }

        internal static string GetSaveWarningMessage(string strFilePath,
            Exception ex, bool bCorruptionWarning)
        {
            var str = string.Empty;
            if (!string.IsNullOrEmpty(strFilePath))
                str += strFilePath + MessageService.NewParagraph;

            str += KLRes.FileSaveFailed;

            if ((ex != null) && !string.IsNullOrEmpty(ex.Message))
                str += MessageService.NewParagraph + ex.Message;

            if (bCorruptionWarning)
                str += MessageService.NewParagraph + KLRes.FileSaveCorruptionWarning;

            return str;
        }

        public static void ExternalIncrementMessageCount() => ++m_uCurrentMessageCount;

        public static void ExternalDecrementMessageCount() => --m_uCurrentMessageCount;
    }
}
