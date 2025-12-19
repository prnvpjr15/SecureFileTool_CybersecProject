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
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>

std::string hmacKey = "default_hmac";
const int KEY_ITERATIONS = 10000;
const int SALT_LEN = 16; // 128-bit Salt

// Load HMAC key from external config file
void LoadConfig() {
    std::ifstream in("config.txt");
    std::string line;
    if (in.is_open()) {
        while (std::getline(in, line)) {
            if (line.find("HMAC_KEY=") == 0) {
                hmacKey = line.substr(9);
            }
        }
    }
}

// Derive AES-256 Key and IV using PBKDF2 with a specific Salt
bool DeriveKeyAndIV(const std::string& password, const CryptoPP::byte* salt, size_t saltLen, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
    const size_t keyLen = CryptoPP::AES::DEFAULT_KEYLENGTH;
    const size_t ivLen = CryptoPP::AES::BLOCKSIZE;
    
    CryptoPP::SecByteBlock derived(keyLen + ivLen);
    
    pbkdf.DeriveKey(
        derived, derived.size(),
        0, 
        (const CryptoPP::byte*)password.data(), password.size(),
        salt, saltLen,
        KEY_ITERATIONS
    );

    std::memcpy(key, derived, keyLen);
    std::memcpy(iv, derived + keyLen, ivLen);
    return true;
}

std::string ToHex(const std::string& data) {
    std::string encoded;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(encoded));
    encoder.Put((const unsigned char*)data.data(), data.size());
    encoder.MessageEnd();
    return encoded;
}

std::string CleanString(std::string s) {
    s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

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
    MyFrame() : wxFrame(NULL, wxID_ANY, "SecureFile Tool v1.0", wxDefaultPosition, wxSize(500, 750)) { 
        wxPanel* panel = new wxPanel(this, wxID_ANY);
        panel->SetDropTarget(new FileDropTarget(this));

        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

        // Header
        wxStaticText* headerTitle = new wxStaticText(panel, wxID_ANY, "SECURE FILE TOOL");
        wxFont titleFont = headerTitle->GetFont();
        titleFont.SetPointSize(16);
        titleFont.SetWeight(wxFONTWEIGHT_BOLD);
        headerTitle->SetFont(titleFont);
        headerTitle->SetForegroundColour(wxColour(60, 60, 60)); 

        wxStaticText* headerSub = new wxStaticText(panel, wxID_ANY, "Encryption & Hashing Utility");
        headerSub->SetForegroundColour(wxColour(100, 100, 100));

        mainSizer->Add(headerTitle, 0, wxALIGN_CENTER | wxTOP, 20);
        mainSizer->Add(headerSub, 0, wxALIGN_CENTER | wxBOTTOM, 20);

        // Section 1: Input
        wxStaticBoxSizer* inputGroup = new wxStaticBoxSizer(wxVERTICAL, panel, "1. Input File");
        wxBoxSizer* inputRow = new wxBoxSizer(wxHORIZONTAL);
        
        uploadBtn = new wxButton(panel, wxID_ANY, " 📂 Open File... ");
        fileLabel = new wxTextCtrl(panel, wxID_ANY, "Drag file here or click Open", wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
        
        inputRow->Add(uploadBtn, 0, wxRIGHT, 10);
        inputRow->Add(fileLabel, 1, wxALIGN_CENTER_VERTICAL);
        inputGroup->Add(inputRow, 0, wxEXPAND | wxALL, 10);
        mainSizer->Add(inputGroup, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 15);

        // Section 2: Operation
        wxStaticBoxSizer* actionGroup = new wxStaticBoxSizer(wxVERTICAL, panel, "2. Operation");
        wxArrayString choices;
        choices.Add("🔒 AES-256 (Encrypt/Decrypt)");
        choices.Add("#️⃣ SHA-256 Hash");
        choices.Add("🔑 HMAC-SHA256 Signature");
        processChoice = new wxChoice(panel, wxID_ANY, wxDefaultPosition, wxDefaultSize, choices);
        processChoice->SetSelection(0);

        descriptionText = new wxStaticText(panel, wxID_ANY, "");
        wxFont descFont = descriptionText->GetFont();
        descFont.SetStyle(wxFONTSTYLE_ITALIC);
        descriptionText->SetFont(descFont);
        descriptionText->SetForegroundColour(wxColour(80, 80, 120)); 

        processBtn = new wxButton(panel, wxID_ANY, "⚙️ RUN PROCESS");
        wxFont btnFont = processBtn->GetFont();
        btnFont.SetWeight(wxFONTWEIGHT_BOLD);
        processBtn->SetFont(btnFont);
        processBtn->SetMinSize(wxSize(-1, 40)); 

        actionGroup->Add(processChoice, 0, wxEXPAND | wxALL, 10);
        actionGroup->Add(descriptionText, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
        actionGroup->Add(processBtn, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
        mainSizer->Add(actionGroup, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 15);

        // Section 3: Output
        wxStaticBoxSizer* outputGroup = new wxStaticBoxSizer(wxVERTICAL, panel, "3. Output & Results");
        
        wxStaticText* resLabel = new wxStaticText(panel, wxID_ANY, "Calculated Result:");
        resultPreview = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 50), wxTE_MULTILINE | wxTE_READONLY);
        
        // Comparator
        wxStaticText* compLabel = new wxStaticText(panel, wxID_ANY, "Paste Expected Hash to Compare (Optional):");
        compareInput = new wxTextCtrl(panel, wxID_ANY, "");
        compareInput->SetHint("e.g. 5e884898da28..."); 
        
        wxBoxSizer* outputBtns = new wxBoxSizer(wxHORIZONTAL);
        downloadBtn = new wxButton(panel, wxID_ANY, "💾 Save to File...");
        copyBtn = new wxButton(panel, wxID_ANY, "📋 Copy Text");
        downloadBtn->Disable();
        copyBtn->Disable();

        outputBtns->Add(downloadBtn, 1, wxRIGHT, 5);
        outputBtns->Add(copyBtn, 1, wxLEFT, 5);

        outputGroup->Add(resLabel, 0, wxLEFT | wxTOP, 10);
        outputGroup->Add(resultPreview, 1, wxEXPAND | wxALL, 5);
        outputGroup->Add(compLabel, 0, wxLEFT | wxTOP, 10); 
        outputGroup->Add(compareInput, 0, wxEXPAND | wxALL, 5); 
        outputGroup->Add(outputBtns, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
        mainSizer->Add(outputGroup, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 15);

        // Status
        statusText = new wxStaticText(panel, wxID_ANY, "Ready.");
        statusText->SetForegroundColour(wxColour(0, 100, 0));
        mainSizer->Add(statusText, 0, wxALL | wxALIGN_LEFT, 15);

        panel->SetSizer(mainSizer);
        Center();
        UpdateDescription(0);

        // Events
        Bind(wxEVT_BUTTON, &MyFrame::OnUpload, this, uploadBtn->GetId());
        Bind(wxEVT_BUTTON, &MyFrame::OnProcess, this, processBtn->GetId());
        Bind(wxEVT_BUTTON, &MyFrame::OnDownload, this, downloadBtn->GetId());
        Bind(wxEVT_BUTTON, &MyFrame::OnCopy, this, copyBtn->GetId());
        Bind(wxEVT_CHOICE, &MyFrame::OnChoiceChanged, this, processChoice->GetId());
        Bind(wxEVT_TEXT, &MyFrame::OnCompareText, this, compareInput->GetId());
    }

    void LoadFileFromPath(const std::string& path) {
        std::ifstream in(path, std::ios::binary);
        if (in) {
            fileName = path;
            inputData.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            fileLabel->SetValue(fileName);
            statusText->SetLabel("Loaded " + std::to_string(inputData.size()) + " bytes.");
            
            outputData.clear();
            resultPreview->Clear();
            compareInput->SetBackgroundColour(wxNullColour); 
            compareInput->Refresh();
            downloadBtn->Disable();
            copyBtn->Disable();
        } else {
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
    wxStaticText* statusText;

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
        std::string calculated = CleanString(resultPreview->GetValue().ToStdString());
        std::string expected = CleanString(compareInput->GetValue().ToStdString());

        if (expected.empty()) {
            compareInput->SetBackgroundColour(wxNullColour); 
        } else if (calculated == expected) {
            compareInput->SetBackgroundColour(wxColour(200, 255, 200)); 
            statusText->SetLabel("MATCH! The file is verified.");
        } else {
            compareInput->SetBackgroundColour(wxColour(255, 200, 200)); 
            statusText->SetLabel("MISMATCH! Hashes do not match.");
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

                CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
                CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
                CryptoPP::byte salt[SALT_LEN];
                bool isDecrypt = (fileName.size() >= 4 && fileName.substr(fileName.size() - 4) == ".enc");
                
                if (isDecrypt) {
                    if (inputData.size() < SALT_LEN) throw std::runtime_error("File too short.");
                    std::memcpy(salt, inputData.data(), SALT_LEN);
                    DeriveKeyAndIV(password, salt, SALT_LEN, key, iv);

                    std::string recovered;
                    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec(key, key.size(), iv);
                    CryptoPP::StringSource(reinterpret_cast<const CryptoPP::byte*>(inputData.data() + SALT_LEN), inputData.size() - SALT_LEN, true, 
                        new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(recovered)));

                    outputData = recovered;
                    statusText->SetLabel("Decryption Complete.");
                    resultPreview->SetValue("[Binary Data Decrypted]");
                    fileName = fileName.substr(0, fileName.size() - 4);
                } else {
                    CryptoPP::AutoSeededRandomPool prng;
                    prng.GenerateBlock(salt, SALT_LEN);
                    DeriveKeyAndIV(password, salt, SALT_LEN, key, iv);

                    std::string cipher;
                    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc(key, key.size(), iv);
                    CryptoPP::StringSource(inputData, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(cipher)));
                    
                    std::string saltString(reinterpret_cast<const char*>(salt), SALT_LEN);
                    outputData = saltString + cipher;
                    statusText->SetLabel("Encryption Complete (Random Salt Applied).");
                    resultPreview->SetValue("[Binary Data Encrypted]");
                    fileName += ".enc";
                }
            } else if (choice == 1) { // SHA-256
                CryptoPP::SHA256 hash;
                std::string digest;
                CryptoPP::StringSource(inputData, true, new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(digest)));
                outputData = ToHex(digest);
                statusText->SetLabel("SHA-256 Calculated.");
                resultPreview->SetValue(outputData);
                CheckHashMatch(); 
            } else if (choice == 2) { // HMAC
                std::string hmacDigest;
                CryptoPP::HMAC<CryptoPP::SHA256> hmac((const CryptoPP::byte*)hmacKey.data(), hmacKey.size());
                CryptoPP::StringSource(inputData, true, new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(hmacDigest)));
                outputData = ToHex(hmacDigest);
                statusText->SetLabel("HMAC Calculated.");
                resultPreview->SetValue(outputData);
                CheckHashMatch();
            }
            downloadBtn->Enable();
            copyBtn->Enable();
        } catch (const std::exception& e) {
            statusText->SetLabel("Error: " + std::string(e.what()));
            wxMessageBox(e.what(), "Error", wxICON_ERROR);
        }
    }

    void OnDownload(wxCommandEvent&) {
        wxFileDialog saveFileDialog(this, _("Save file"), "", fileName, "All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (saveFileDialog.ShowModal() == wxID_CANCEL) return;
        std::ofstream out(saveFileDialog.GetPath().ToStdString(), std::ios::binary);
        out << outputData;
        statusText->SetLabel("File saved successfully.");
    }

    void OnCopy(wxCommandEvent&) {
        if (wxTheClipboard->Open()) {
            if (resultPreview->GetValue().StartsWith("[")) wxMessageBox("Binary data cannot be copied.", "Info", wxICON_INFORMATION);
            else {
                wxTheClipboard->SetData(new wxTextDataObject(resultPreview->GetValue()));
                statusText->SetLabel("Copied to clipboard!");
            }
            wxTheClipboard->Close();
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
        LoadConfig();
        MyFrame* frame = new MyFrame();
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(MyApp);