/**
 * SecureFileTool v1.0
 * A C++ Desktop Utility for AES-256 Encryption, SHA-256 Hashing, and HMAC Signing.
 * * Dependencies:
 * - wxWidgets 3.x (GUI)
 * - Crypto++ 8.x (Cryptographic Primitives)
 */

#include <wx/wx.h>
#include <wx/filedlg.h>
#include <wx/progdlg.h>
#include <wx/textdlg.h>
#include <wx/statline.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/dnd.h>

#include "crypto_utils.h"
#include "file_io.h"
#include "audit_log.h"
#include <fstream>

using namespace std;


class MyFrame;

// --- Drag & Drop Handler ---
class FileDropTarget : public wxFileDropTarget {
public:
    FileDropTarget(MyFrame* pOwner);
    virtual bool OnDropFiles(wxCoord x, wxCoord y, const wxArrayString& filenames) override;
private:
    MyFrame* m_pOwner;
};

// --- Main GUI Window ---
class MyFrame : public wxFrame {
public:
    MyFrame() : wxFrame(NULL, wxID_ANY, "SecureFileTool v1.0", wxDefaultPosition, wxSize(700, 950)) { 
        wxPanel* mainPanel = new wxPanel(this, wxID_ANY);
        mainPanel->SetBackgroundColour(wxColour(250, 250, 252)); // Off-white
        mainPanel->SetDropTarget(new FileDropTarget(this));

        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

        // ===== HEADER BANNER =====
        wxPanel* headerPanel = new wxPanel(mainPanel, wxID_ANY);
        headerPanel->SetBackgroundColour(wxColour(13, 71, 161)); // Dark blue
        wxBoxSizer* headerSizer = new wxBoxSizer(wxVERTICAL);
        
        wxStaticText* headerTitle = new wxStaticText(headerPanel, wxID_ANY, "🔐 SECURE FILE TOOL");
        wxFont titleFont = headerTitle->GetFont();
        titleFont.SetPointSize(20);
        titleFont.SetWeight(wxFONTWEIGHT_BOLD);
        headerTitle->SetFont(titleFont);
        headerTitle->SetForegroundColour(*wxWHITE);

        wxStaticText* headerSub = new wxStaticText(headerPanel, wxID_ANY, 
            "Professional Encryption, Hashing & Integrity Verification");
        wxFont subFont = headerSub->GetFont();
        subFont.SetPointSize(10);
        headerSub->SetFont(subFont);
        headerSub->SetForegroundColour(wxColour(187, 222, 251)); // Light blue

        headerSizer->Add(headerTitle, 0, wxALL, 14);
        headerSizer->Add(headerSub, 0, wxLEFT | wxRIGHT | wxBOTTOM, 14);
        headerPanel->SetSizer(headerSizer);
        mainSizer->Add(headerPanel, 0, wxEXPAND);

        // Scroll area for content
        wxScrolledWindow* scrollPanel = new wxScrolledWindow(mainPanel, wxID_ANY);
        scrollPanel->SetScrollRate(0, 5);
        scrollPanel->SetBackgroundColour(wxColour(250, 250, 252));
        wxBoxSizer* scrollSizer = new wxBoxSizer(wxVERTICAL);

        // ===== STEP 1: INPUT FILE =====
        wxPanel* step1Panel = new wxPanel(scrollPanel, wxID_ANY);
        step1Panel->SetBackgroundColour(wxColour(227, 242, 253)); // Light blue #E3F2FD
        wxBoxSizer* step1Sizer = new wxBoxSizer(wxVERTICAL);

        wxStaticText* step1Title = new wxStaticText(step1Panel, wxID_ANY, "📂  STEP 1: SELECT & LOAD FILE");
        wxFont stepTitleFont = step1Title->GetFont();
        stepTitleFont.SetPointSize(12);
        stepTitleFont.SetWeight(wxFONTWEIGHT_BOLD);
        step1Title->SetFont(stepTitleFont);
        step1Title->SetForegroundColour(wxColour(13, 71, 161)); // Match header

        wxBoxSizer* inputRow = new wxBoxSizer(wxHORIZONTAL);
        uploadBtn = new wxButton(step1Panel, wxID_ANY, "📁  Browse File");
        uploadBtn->SetToolTip("Click to open file dialog or drag & drop a file");
        uploadBtn->SetMinSize(wxSize(130, 36));
        
        fileLabel = new wxTextCtrl(step1Panel, wxID_ANY, "No file loaded - Drag & drop here", 
                                    wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
        fileLabel->SetBackgroundColour(*wxWHITE);
        fileLabel->SetForegroundColour(wxColour(100, 100, 100));
        
        inputRow->Add(uploadBtn, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, 12);
        inputRow->Add(fileLabel, 1, wxALIGN_CENTER_VERTICAL);

        step1Sizer->Add(step1Title, 0, wxLEFT | wxTOP | wxRIGHT, 16);
        step1Sizer->Add(5, 8, 0); // Spacer
        step1Sizer->Add(inputRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 16);
        step1Panel->SetSizer(step1Sizer);
        scrollSizer->Add(step1Panel, 0, wxEXPAND | wxALL, 12);

        // ===== STEP 2: OPERATION SELECTION =====
        wxPanel* step2Panel = new wxPanel(scrollPanel, wxID_ANY);
        step2Panel->SetBackgroundColour(wxColour(255, 243, 224)); // Light orange #FFF3E0
        wxBoxSizer* step2Sizer = new wxBoxSizer(wxVERTICAL);

        wxStaticText* step2Title = new wxStaticText(step2Panel, wxID_ANY, "⚙️  STEP 2: CHOOSE OPERATION");
        step2Title->SetFont(stepTitleFont);
        step2Title->SetForegroundColour(wxColour(230, 124, 15)); // Orange

        wxStaticText* opLabel = new wxStaticText(step2Panel, wxID_ANY, "Select Operation:");
        wxFont labelFont = opLabel->GetFont();
        labelFont.SetWeight(wxFONTWEIGHT_BOLD);
        opLabel->SetFont(labelFont);

        wxArrayString choices;
        choices.Add("🔒  AES-256 Encrypt / Decrypt");
        choices.Add("🔢  SHA-256 Hash");
        choices.Add("🔐  HMAC-SHA256 Sign");
        processChoice = new wxChoice(step2Panel, wxID_ANY, wxDefaultPosition, wxSize(-1, 32), choices);
        processChoice->SetSelection(0);
        processChoice->SetToolTip("Select the cryptographic operation to perform");

        descriptionText = new wxStaticText(step2Panel, wxID_ANY, "");
        wxFont descFont = descriptionText->GetFont();
        descFont.SetStyle(wxFONTSTYLE_ITALIC);
        descFont.SetPointSize(9);
        descriptionText->SetFont(descFont);
        descriptionText->SetForegroundColour(wxColour(84, 84, 84));
        descriptionText->SetMinSize(wxSize(-1, 50));

        processBtn = new wxButton(step2Panel, wxID_ANY, "▶  RUN OPERATION");
        wxFont btnFont = processBtn->GetFont();
        btnFont.SetWeight(wxFONTWEIGHT_BOLD);
        btnFont.SetPointSize(11);
        processBtn->SetFont(btnFont);
        processBtn->SetMinSize(wxSize(-1, 48));
        processBtn->SetBackgroundColour(wxColour(56, 142, 60)); // Green
        processBtn->SetForegroundColour(*wxWHITE);
        processBtn->SetToolTip("Execute the operation (Ctrl+Enter)");

        step2Sizer->Add(step2Title, 0, wxLEFT | wxTOP | wxRIGHT, 16);
        step2Sizer->Add(5, 8, 0);
        step2Sizer->Add(opLabel, 0, wxLEFT | wxRIGHT, 16);
        step2Sizer->Add(5, 4, 0);
        step2Sizer->Add(processChoice, 0, wxEXPAND | wxLEFT | wxRIGHT, 16);
        step2Sizer->Add(10, 10, 0);
        step2Sizer->Add(descriptionText, 0, wxEXPAND | wxLEFT | wxRIGHT, 16);
        step2Sizer->Add(10, 10, 0);
        step2Sizer->Add(processBtn, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 16);
        step2Panel->SetSizer(step2Sizer);
        scrollSizer->Add(step2Panel, 0, wxEXPAND | wxALL, 12);

        // ===== STEP 3: OUTPUT & RESULTS =====
        wxPanel* step3Panel = new wxPanel(scrollPanel, wxID_ANY);
        step3Panel->SetBackgroundColour(wxColour(232, 245, 233)); // Light green #E8F5E9
        wxBoxSizer* step3Sizer = new wxBoxSizer(wxVERTICAL);

        wxStaticText* step3Title = new wxStaticText(step3Panel, wxID_ANY, "📊  STEP 3: VIEW OUTPUT & VERIFY");
        step3Title->SetFont(stepTitleFont);
        step3Title->SetForegroundColour(wxColour(27, 94, 32)); // Dark green

        wxStaticText* resLabel = new wxStaticText(step3Panel, wxID_ANY, "Result:");
        resLabel->SetFont(labelFont);
        resultPreview = new wxTextCtrl(step3Panel, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 75), 
                                       wxTE_MULTILINE | wxTE_READONLY | wxTE_WORDWRAP);
        resultPreview->SetBackgroundColour(*wxWHITE);
        resultPreview->SetToolTip("The output from your operation will appear here");

        wxStaticText* compLabel = new wxStaticText(step3Panel, wxID_ANY, "Optional: Paste Expected Hash to Compare:");
        compLabel->SetFont(labelFont);
        compareInput = new wxTextCtrl(step3Panel, wxID_ANY, "");
        compareInput->SetHint("Paste a known hash for verification...");
        compareInput->SetToolTip("Compare outputs (Green=Match, Red=Mismatch)");
        compareInput->SetMinSize(wxSize(-1, 32));

        wxBoxSizer* outputBtns = new wxBoxSizer(wxHORIZONTAL);
        downloadBtn = new wxButton(step3Panel, wxID_ANY, "💾  Save");
        downloadBtn->SetToolTip("Save output to file");
        downloadBtn->SetMinSize(wxSize(90, 36));
        downloadBtn->Disable();
        
        copyBtn = new wxButton(step3Panel, wxID_ANY, "📋  Copy");
        copyBtn->SetToolTip("Copy to clipboard");
        copyBtn->SetMinSize(wxSize(90, 36));
        copyBtn->Disable();
        
        viewLogBtn = new wxButton(step3Panel, wxID_ANY, "📜  Audit Log");
        viewLogBtn->SetToolTip("View operation history");
        viewLogBtn->SetMinSize(wxSize(110, 36));

        outputBtns->Add(downloadBtn, 0, wxRIGHT, 8);
        outputBtns->Add(copyBtn, 0, wxRIGHT, 8);
        outputBtns->Add(viewLogBtn, 0, wxLEFT, 0);
        outputBtns->AddStretchSpacer();

        step3Sizer->Add(step3Title, 0, wxLEFT | wxTOP | wxRIGHT, 16);
        step3Sizer->Add(5, 8, 0);
        step3Sizer->Add(resLabel, 0, wxLEFT | wxRIGHT, 16);
        step3Sizer->Add(5, 4, 0);
        step3Sizer->Add(resultPreview, 0, wxEXPAND | wxLEFT | wxRIGHT, 16);
        step3Sizer->Add(10, 10, 0);
        step3Sizer->Add(compLabel, 0, wxLEFT | wxRIGHT, 16);
        step3Sizer->Add(5, 4, 0);
        step3Sizer->Add(compareInput, 0, wxEXPAND | wxLEFT | wxRIGHT, 16);
        step3Sizer->Add(10, 10, 0);
        step3Sizer->Add(outputBtns, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 16);
        step3Panel->SetSizer(step3Sizer);
        scrollSizer->Add(step3Panel, 0, wxEXPAND | wxALL, 12);

        // ===== STATUS BAR =====
        wxPanel* statusPanel = new wxPanel(scrollPanel, wxID_ANY);
        statusPanel->SetBackgroundColour(wxColour(241, 241, 241));
        wxBoxSizer* statusBar = new wxBoxSizer(wxHORIZONTAL);
        statusIcon = new wxStaticText(statusPanel, wxID_ANY, "●");
        statusIcon->SetForegroundColour(wxColour(56, 142, 60)); // Green
        
        statusText = new wxStaticText(statusPanel, wxID_ANY, "Ready");
        statusText->SetForegroundColour(wxColour(56, 142, 60));
        wxFont statusFont = statusText->GetFont();
        statusFont.SetWeight(wxFONTWEIGHT_BOLD);
        statusText->SetFont(statusFont);

        statusBar->Add(statusIcon, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, 10);
        statusBar->Add(statusText, 1, wxALIGN_CENTER_VERTICAL);
        statusPanel->SetSizer(statusBar);
        scrollSizer->Add(statusPanel, 0, wxEXPAND | wxALL, 12);

        // ===== AUDIT LOG VIEWER =====
        wxPanel* logPanel = new wxPanel(scrollPanel, wxID_ANY);
        logPanel->SetBackgroundColour(wxColour(245, 245, 247));
        wxBoxSizer* logSizer = new wxBoxSizer(wxVERTICAL);

        wxStaticText* logTitle = new wxStaticText(logPanel, wxID_ANY, "📋  AUDIT LOG");
        logTitle->SetFont(stepTitleFont);
        logTitle->SetForegroundColour(wxColour(66, 133, 244)); // Blue

        auditLogText = new wxTextCtrl(logPanel, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 120),
                                       wxTE_MULTILINE | wxTE_READONLY | wxTE_WORDWRAP);
        auditLogText->SetBackgroundColour(*wxWHITE);
        auditLogText->SetToolTip("Audit log of all cryptographic operations");

        wxBoxSizer* logBtns = new wxBoxSizer(wxHORIZONTAL);
        refreshLogBtn = new wxButton(logPanel, wxID_ANY, "🔄  Refresh");
        refreshLogBtn->SetToolTip("Reload from disk");
        refreshLogBtn->SetMinSize(wxSize(100, 32));
        
        clearLogBtn = new wxButton(logPanel, wxID_ANY, "🗑️  Clear");
        clearLogBtn->SetToolTip("Delete all entries");
        clearLogBtn->SetMinSize(wxSize(100, 32));

        logBtns->Add(refreshLogBtn, 0, wxRIGHT, 8);
        logBtns->Add(clearLogBtn, 0);
        logBtns->AddStretchSpacer();

        logSizer->Add(logTitle, 0, wxLEFT | wxTOP | wxRIGHT, 16);
        logSizer->Add(5, 8, 0);
        logSizer->Add(auditLogText, 1, wxEXPAND | wxLEFT | wxRIGHT, 16);
        logSizer->Add(5, 8, 0);
        logSizer->Add(logBtns, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 16);
        logPanel->SetSizer(logSizer);
        
        auditLogPanel = logPanel;
        logPanel->Hide();
        scrollSizer->Add(logPanel, 0, wxEXPAND | wxALL, 12);

        scrollPanel->SetSizer(scrollSizer);
        mainSizer->Add(scrollPanel, 1, wxEXPAND);

        // Apply main sizer
        mainPanel->SetSizer(mainSizer);
        Center();
        UpdateDescription(0);

        // ===== KEYBOARD SHORTCUTS =====
        wxAcceleratorEntry acc[1];
        acc[0].Set(wxACCEL_CTRL, WXK_RETURN, processBtn->GetId());
        wxAcceleratorTable accel(1, acc);
        SetAcceleratorTable(accel);

        // ===== EVENT BINDINGS =====
        Bind(wxEVT_BUTTON, &MyFrame::OnUpload, this, uploadBtn->GetId());
        Bind(wxEVT_BUTTON, &MyFrame::OnProcess, this, processBtn->GetId());
        Bind(wxEVT_BUTTON, &MyFrame::OnDownload, this, downloadBtn->GetId());
        Bind(wxEVT_BUTTON, &MyFrame::OnCopy, this, copyBtn->GetId());
        Bind(wxEVT_BUTTON, &MyFrame::OnViewLog, this, viewLogBtn->GetId());
        Bind(wxEVT_BUTTON, &MyFrame::OnRefreshLog, this, refreshLogBtn->GetId());
        Bind(wxEVT_BUTTON, &MyFrame::OnClearLog, this, clearLogBtn->GetId());
        Bind(wxEVT_CHOICE, &MyFrame::OnChoiceChanged, this, processChoice->GetId());
        Bind(wxEVT_TEXT, &MyFrame::OnCompareText, this, compareInput->GetId());
    }

    void LoadFileFromPath(const std::string& path) {
        std::string data;
        if (FileIO::ReadFile(path, data)) {
            fileName = path;
            inputData = std::move(data);
            fileLabel->SetValue(fileName);
            statusText->SetLabel("✓ Loaded " + std::to_string(inputData.size()) + " bytes.");
            UpdateStatusColor(true);

            outputData.clear();
            resultPreview->Clear();
            compareInput->SetBackgroundColour(wxNullColour);
            compareInput->Refresh();
            downloadBtn->Disable();
            copyBtn->Disable();
        } else {
            statusText->SetLabel("✗ Failed to open file.");
            UpdateStatusColor(false);
            wxMessageBox("Failed to open file.", "Error", wxICON_ERROR);
        }
    }

private:
    wxButton* uploadBtn;
    wxTextCtrl* fileLabel;
    wxChoice* processChoice;
    wxStaticText* descriptionText;
    wxButton* processBtn;
    wxTextCtrl* resultPreview;
    wxTextCtrl* compareInput;
    wxButton* downloadBtn;
    wxButton* copyBtn;
    wxButton* viewLogBtn;
    wxButton* refreshLogBtn;
    wxButton* clearLogBtn;
    wxStaticText* statusText;
    wxStaticText* statusIcon;
    wxTextCtrl* auditLogText;
    wxPanel* auditLogPanel;
    bool auditLogVisible = false;

    std::string inputData;

    std::string outputData;
    std::string fileName;

    void UpdateDescription(int selection) {
        std::string desc;
        switch(selection) {
            case 0: desc = "Advanced Encryption Standard (AES). Uses a random salt & password to scramble data."; break;
            case 1: desc = "Secure Hash Algorithm (SHA-256). Creates a unique fingerprint to verify file integrity."; break;
            case 2: desc = "HMAC-SHA256. Verifies authenticity using the secret key in 'config.txt'."; break;
            default: desc = "";
        }
        descriptionText->SetLabel(desc);
        descriptionText->Wrap(420);
        Layout();
    }

    void CheckHashMatch() {
        std::string calculated = CryptoUtils::CleanString(resultPreview->GetValue().ToStdString());
        std::string expected = CryptoUtils::CleanString(compareInput->GetValue().ToStdString());

        if (expected.empty()) {
            compareInput->SetBackgroundColour(wxNullColour);
        } else if (calculated == expected) {
            compareInput->SetBackgroundColour(wxColour(144, 238, 144)); // Light green
            statusText->SetLabel("✓ MATCH! The file is verified.");
            UpdateStatusColor(true);
        } else {
            compareInput->SetBackgroundColour(wxColour(255, 182, 193)); // Light red
            statusText->SetLabel("✗ MISMATCH! Hashes do not match.");
            UpdateStatusColor(false);
        }
        compareInput->Refresh();
    }

    void OnCompareText(wxCommandEvent&) { CheckHashMatch(); }
    void OnChoiceChanged(wxCommandEvent& event) { UpdateDescription(event.GetSelection()); }
    void OnUpload(wxCommandEvent&) {
        wxFileDialog openFileDialog(this, _("Open file"), "", "", "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (openFileDialog.ShowModal() == wxID_CANCEL) return;
        LoadFileFromPath(openFileDialog.GetPath().ToStdString());
    }

    void OnProcess(wxCommandEvent&) {
        if (inputData.empty()) {
            wxMessageBox("Please select a file first.", "Warning", wxICON_WARNING);
            return;
        }
        try {
            int choice = processChoice->GetSelection();
            wxBusyCursor busy;
            compareInput->SetBackgroundColour(wxNullColour);
            compareInput->Refresh();

            if (choice == 0) { // AES
                wxPasswordEntryDialog pwDlg(this, "Enter Password:", "Security Check");
                if (pwDlg.ShowModal() != wxID_OK) return;
                std::string password = pwDlg.GetValue().ToStdString();

                bool isDecrypt = (fileName.size() >= 4 && fileName.substr(fileName.size() - 4) == ".enc");
                std::string result;
                if (isDecrypt) {
                    if (!CryptoUtils::AesDecryptWithLog(password, inputData, result, fileName))
                        throw std::runtime_error("AES decryption failed or file corrupt.");
                    outputData = std::move(result);
                    statusText->SetLabel("✓ Decryption Complete.");
                    UpdateStatusColor(true);
                    resultPreview->SetValue("[Binary Data Decrypted]");
                    fileName = fileName.substr(0, fileName.size() - 4);
                } else {
                    if (!CryptoUtils::AesEncryptWithLog(password, inputData, result, fileName))
                        throw std::runtime_error("AES encryption failed.");
                    outputData = std::move(result);
                    statusText->SetLabel("✓ Encryption Complete (Random Salt Applied).");
                    UpdateStatusColor(true);
                    resultPreview->SetValue("[Binary Data Encrypted]");
                    fileName += ".enc";
                }
            } else if (choice == 1) { // SHA-256
                outputData = CryptoUtils::Sha256WithLog(inputData, fileName);
                statusText->SetLabel("✓ SHA-256 Calculated.");
                UpdateStatusColor(true);
                resultPreview->SetValue(outputData);
                CheckHashMatch();
            } else if (choice == 2) { // HMAC
                outputData = CryptoUtils::HmacSha256WithLog(inputData, FileIO::hmacKey, fileName);
                statusText->SetLabel("✓ HMAC Calculated.");
                UpdateStatusColor(true);
                resultPreview->SetValue(outputData);
                CheckHashMatch();
            }
            downloadBtn->Enable();
            copyBtn->Enable();
        } catch (const std::exception& e) {
            statusText->SetLabel("✗ Error: " + std::string(e.what()));
            UpdateStatusColor(false);
            wxMessageBox(e.what(), "Operation Failed", wxICON_ERROR);
        }
    }

    void OnDownload(wxCommandEvent&) {
        wxFileDialog saveFileDialog(this, _("Save file"), "", fileName, "All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (saveFileDialog.ShowModal() == wxID_CANCEL) return;
        if (FileIO::WriteFile(saveFileDialog.GetPath().ToStdString(), outputData)) {
            statusText->SetLabel("✓ File saved successfully.");
            UpdateStatusColor(true);
        } else {
            statusText->SetLabel("✗ Unable to save file.");
            UpdateStatusColor(false);
            wxMessageBox("Unable to save file.", "Error", wxICON_ERROR);
        }
    }

    void OnCopy(wxCommandEvent&) {
        if (wxTheClipboard->Open()) {
            if (resultPreview->GetValue().StartsWith("[")) wxMessageBox("Binary data cannot be copied.", "Info", wxICON_INFORMATION);
            else {
                wxTheClipboard->SetData(new wxTextDataObject(resultPreview->GetValue()));
                statusText->SetLabel("Copied to clipboard!");
                statusIcon->SetForegroundColour(wxColour(76, 175, 80));
            }
            wxTheClipboard->Close();
        }
    }

    void OnViewLog(wxCommandEvent&) {
        auditLogVisible = !auditLogVisible;
        if (auditLogVisible) {
            auditLogPanel->Show();
            OnRefreshLog(wxCommandEvent());
        } else {
            auditLogPanel->Hide();
        }
        Layout();
    }

    void OnRefreshLog(wxCommandEvent&) {
        auditLogText->Clear();
        std::ifstream logfile(AuditLog::GetLogFilePath());
        if (logfile.is_open()) {
            std::string line;
            while (std::getline(logfile, line)) {
                auditLogText->AppendText(line + "\n");
            }
            logfile.close();
        } else {
            auditLogText->AppendText("(No audit log entries yet)");
        }
    }

    void OnClearLog(wxCommandEvent&) {
        int result = wxMessageBox("Are you sure you want to clear the audit log? This cannot be undone.",
                                  "Confirm Clear", wxYES_NO | wxICON_WARNING);
        if (result == wxYES) {
            AuditLog::ClearLog();
            auditLogText->Clear();
            statusText->SetLabel("Audit log cleared.");
            statusIcon->SetForegroundColour(wxColour(255, 152, 0)); // Orange
        }
    }

    void UpdateStatusColor(bool success) {
        if (success) {
            statusIcon->SetForegroundColour(wxColour(76, 175, 80)); // Green
            statusText->SetForegroundColour(wxColour(76, 175, 80));
        } else {
            statusIcon->SetForegroundColour(wxColour(244, 67, 54)); // Red
            statusText->SetForegroundColour(wxColour(244, 67, 54));
        }
    }
};

FileDropTarget::FileDropTarget(MyFrame* pOwner) { m_pOwner = pOwner; }
bool FileDropTarget::OnDropFiles(wxCoord x, wxCoord y, const wxArrayString& filenames) {
    if (filenames.GetCount() > 0) {
        m_pOwner->LoadFileFromPath(filenames[0].ToStdString());
        return true;
    }
    return false;
}

class MyApp : public wxApp {
public:
    virtual bool OnInit() {
        FileIO::LoadConfig();
        MyFrame* frame = new MyFrame();
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(MyApp);