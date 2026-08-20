using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Navigation;
using System.Windows.Threading;
using Microsoft.Win32;
using ZXing;

namespace MasterAuthenticator
{
    public partial class MainWindow : Window
    {
        // ----------------------------------------------------
        // Global variables & state
        // ----------------------------------------------------
        private readonly SecurityManager _security = new SecurityManager();
        private readonly DispatcherTimer _totpTimer = new DispatcherTimer();
        // Use the platform's normal HTTPS certificate validation.
        private readonly HttpClient _httpClient = new HttpClient();
        
        // This holds the collection of accounts currently bound to the UI
        private readonly ObservableCollection<AccountViewModel> _accountViewModels = new ObservableCollection<AccountViewModel>();
        
        private GoogleAccount? _editingAccount = null;
        private string _currentTab = "accounts";
        private bool _backupCodesExpanded = false;
        private string _currentPasswordHash = "";
        private string _currentServerUpdatedAt = "";
        private bool _setupOfflineChoice = false; // בחירת המשתמש באשף ההפעלה הראשונה

        // כתובת שרת הגיבוי החדש (Cloudflare Worker) - החלף את YOUR_WORKERS_SUBDOMAIN בסאבדומיין שקיבלת מ-Cloudflare
        private const string DeveloperScriptUrl = "https://master-auth-backup.mytovmail.workers.dev";

        // מפתח API אופציונלי (רק אם הוגדר גם ב-Worker) - ריק = ללא אימות
        private const string DeveloperApiToken = "";

        public MainWindow()
        {
            InitializeComponent();

            // שליחת מפתח ה-API בכל בקשה לשרת הגיבוי אם הוגדר
            if (!string.IsNullOrEmpty(DeveloperApiToken))
            {
                _httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", DeveloperApiToken);
            }
            
            // Set ItemsSource for the accounts list
            AccountsList.ItemsSource = _accountViewModels;
            
            // Setup TOTP tick timer
            _totpTimer.Interval = TimeSpan.FromSeconds(1);
            _totpTimer.Tick += TotpTimer_Tick;
            _totpTimer.Start();

            // Check configuration on load
            Loaded += MainWindow_Loaded;
            NetworkChange.NetworkAvailabilityChanged += NetworkAvailabilityChanged;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _security.LoadAppSettings();
            UpdateLockScreenForMode();

            if (_security.IsFirstRun())
            {
                // הפעלה ראשונה — אשף בחירת מצב הסנכרון לפני מסך הנעילה
                SelectSetupOption(false);
                ShowScreen("Setup");
            }
            else
            {
                ShowScreen("Lock");
                LockEmail.Focus();
            }

            UpdateSyncBadgeStatus();
        }

        private async void NetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
        {
            if (e.IsAvailable && !_security.IsOfflineMode && _security.IsUnlocked() && _security.HasPendingLocalSync(_security.GetRecoveryEmail()))
            {
                await SyncVaultToCloudAsync();
            }
        }

        private void UpdateLockScreenForMode()
        {
            bool offline = _security.IsOfflineMode;
            LockIcon.Text = offline ? "📴" : "☁️";
            LockTitleText.Text = offline ? "מצב אופליין" : "חיבור מאובטח לענן";
            LockModeHint.Visibility = offline ? Visibility.Visible : Visibility.Collapsed;
        }

        // ----------------------------------------------------
        // Navigation & Screen Management
        // ----------------------------------------------------
        private void ShowScreen(string screenName)
        {
            SetupScreen.Visibility = screenName == "Setup" ? Visibility.Visible : Visibility.Collapsed;
            LockScreen.Visibility = screenName == "Lock" ? Visibility.Visible : Visibility.Collapsed;
            DashboardScreen.Visibility = screenName == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        }

        // ----------------------------------------------------
        // First-Run Setup Screen (sync mode choice)
        // ----------------------------------------------------
        private void SelectSetupOption(bool offline)
        {
            _setupOfflineChoice = offline;

            SyncOptionCard.BorderBrush = offline ? new SolidColorBrush(Color.FromArgb(21, 255, 255, 255)) : new SolidColorBrush(Color.FromRgb(139, 92, 246));
            SyncOptionCard.BorderThickness = offline ? new Thickness(1.5) : new Thickness(2);
            SyncOptionCheck.Visibility = offline ? Visibility.Collapsed : Visibility.Visible;

            OfflineOptionCard.BorderBrush = offline ? new SolidColorBrush(Color.FromRgb(139, 92, 246)) : new SolidColorBrush(Color.FromArgb(21, 255, 255, 255));
            OfflineOptionCard.BorderThickness = offline ? new Thickness(2) : new Thickness(1.5);
            OfflineOptionCheck.Visibility = offline ? Visibility.Visible : Visibility.Collapsed;
        }

        private void SyncOptionCard_Click(object sender, MouseButtonEventArgs e) => SelectSetupOption(false);

        private void OfflineOptionCard_Click(object sender, MouseButtonEventArgs e) => SelectSetupOption(true);

        private void SetupContinue_Click(object sender, RoutedEventArgs e)
        {
            // שמירת ההעדפה סוגרת את אשף ההפעלה הראשונה (נוצר קובץ settings.json)
            _security.SetOfflineMode(_setupOfflineChoice);
            UpdateLockScreenForMode();
            ShowScreen("Lock");
            LockEmail.Focus();
            UpdateSyncBadgeStatus();
            ShowToast(_setupOfflineChoice
                ? "מצב אופליין נבחר — הנתונים יישארו במחשב זה בלבד. 📴"
                : "מצב סנכרון נבחר — ניתן להתחבר לשרת הגיבוי. ☁️", false);
        }

        private void SwitchTab(string tabName)
        {
            _currentTab = tabName;
            
            // Update tab button highlights
            TabAccountsBtn.Tag = tabName == "accounts" ? "Active" : null;
            TabGuideBtn.Tag = tabName == "guide" ? "Active" : null;
            TabSettingsBtn.Tag = tabName == "settings" ? "Active" : null;

            // Trigger updates in resources
            TabAccountsBtn.Style = (Style)FindResource("TabButton");
            TabGuideBtn.Style = (Style)FindResource("TabButton");
            TabSettingsBtn.Style = (Style)FindResource("TabButton");

            // Toggle views
            AccountsView.Visibility = tabName == "accounts" ? Visibility.Visible : Visibility.Collapsed;
            GuideView.Visibility = tabName == "guide" ? Visibility.Visible : Visibility.Collapsed;
            SettingsView.Visibility = tabName == "settings" ? Visibility.Visible : Visibility.Collapsed;

            if (tabName == "accounts")
            {
                LoadAccountsList();
            }
            else if (tabName == "settings")
            {
                LoadSettingsData();
            }
        }

        // ----------------------------------------------------
        // Lock & Connection Screen Handlers
        // ----------------------------------------------------
        private async void UnlockSubmitButton_Click(object sender, RoutedEventArgs e)
        {
            await ConnectAndUnlockVaultAsync();
        }

        private async void LockPassword_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                await ConnectAndUnlockVaultAsync();
            }
        }

        private async Task ConnectAndUnlockVaultAsync()
        {
            string email = LockEmail.Text.Trim().ToLower();
            string password = LockPassword.Password;

            if (string.IsNullOrEmpty(email) || !email.Contains("@"))
            {
                ShowToast("אנא הזן כתובת אימייל תקינה!", true);
                return;
            }

            if (password.Length < 4)
            {
                ShowToast("הסיסמה חייבת להיות באורך 4 תווים לפחות!", true);
                return;
            }

            if (_security.IsOfflineMode)
            {
                await UnlockOfflineAsync(email, password);
                return;
            }

            ShowToast("מתחבר לשרת הגיבוי... נא להמתין", false);

            try
            {
                // Request vault data by email
                var payload = new { action = "get_vault", email = email, password = HashPassword(password), clientVersion = "secure-v1" };
                string jsonReq = JsonSerializer.Serialize(payload);
                var content = new StringContent(jsonReq, Encoding.UTF8, "application/json");

                HttpResponseMessage response = await _httpClient.PostAsync(DeveloperScriptUrl, content);
                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    // השרת זמין ותקין - הסיסמה אינה תואמת לגיבוב המאובטח השמור בענן.
                    ShowToast("סיסמת המאסטר שגויה. נסה שנית!", true);
                    return;
                }
                if (!response.IsSuccessStatusCode)
                {
                    throw new HttpRequestException("שרת הגיבוי אינו זמין (HTTP " + (int)response.StatusCode + ")");
                }

                string responseString = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<GetVaultResult>(responseString);

                if (result == null || !result.success)
                {
                    string errMsg = result != null && !string.IsNullOrEmpty(result.message) ? result.message : "שגיאה בקבלת נתונים מהשרת!";
                    ShowToast(errMsg, true);
                    return;
                }

                if (result.registered)
                {
                    // Existing user
                    if (string.IsNullOrEmpty(result.vault))
                    {
                        ShowToast("הכספת בענן ריקה או פגומה!", true);
                        return;
                    }

                    if (_security.LoadVault(result.vault, password))
                    {
                        _currentPasswordHash = HashPassword(password);
                        _currentServerUpdatedAt = result.updatedAt ?? "";
                        _security.SaveLocalVault(email, _currentServerUpdatedAt, false);
                        ShowToast("נעילת המאמת נפתחה בהצלחה.", false);
                        LockPassword.Password = "";
                        ShowScreen("Dashboard");
                        SwitchTab("accounts");
                        UpdateSyncBadgeStatus();
                        _ = SyncVaultToCloudAsync();
                    }
                    else
                    {
                        ShowToast("סיסמת המאסטר שגויה. נסה שנית!", true);
                    }
                }
                else
                {
                    // Email not registered
                    bool registerResult = ShowCustomDialog("חשבון חדש", $"כתובת האימייל {email} אינה רשומה בענן.\n\nהאם ברצונך ליצור כספת מאובטחת חדשה עבור אימייל זה עם הסיסמה שהזנת?", true, "❓");

                    if (registerResult)
                    {
                        // Confirm password to prevent typos
                        string confirmPassword = AskUserPasswordCustomDialog("אימות סיסמה מחדש", "אנא הקלד שוב את סיסמת המאסטר שקבעת לצורך אימות:", "אישור 🔑");
                        if (string.IsNullOrEmpty(confirmPassword))
                        {
                            return;
                        }

                        if (password != confirmPassword)
                        {
                            ShowToast("הסיסמאות אינן תואמות! תהליך הרישום בוטל.", true);
                            return;
                        }

                        // Initialize empty vault
                        string vaultJson = _security.InitializeNewVault(password, email);
                        _currentPasswordHash = HashPassword(password);

                        // Save new vault to cloud
                        ShowToast("יוצר חשבון בענן... נא להמתין", false);
                        var savePayload = new { action = "save_vault", email = email, password = _currentPasswordHash, vault = vaultJson, clientVersion = "secure-v1" };
                        string saveJsonReq = JsonSerializer.Serialize(savePayload);
                        var saveContent = new StringContent(saveJsonReq, Encoding.UTF8, "application/json");

                        HttpResponseMessage saveResponse = await _httpClient.PostAsync(DeveloperScriptUrl, saveContent);
                        if (saveResponse.IsSuccessStatusCode)
                        {
                            string saveResponseString = await saveResponse.Content.ReadAsStringAsync();
                            var saveResult = JsonSerializer.Deserialize<GetVaultResult>(saveResponseString);
                            if (saveResult != null && saveResult.success)
                            {
                                _currentServerUpdatedAt = saveResult.updatedAt ?? "";
                                _security.SaveLocalVault(email, _currentServerUpdatedAt, false);
                                ShowToast("חשבון ענן חדש נוצר וסונכרן בהצלחה!", false);
                                LockPassword.Password = "";
                                ShowScreen("Dashboard");
                                SwitchTab("accounts");
                                UpdateSyncBadgeStatus();
                                _ = SyncVaultToCloudAsync();
                            }
                            else
                            {
                                string errMsg = saveResult != null && !string.IsNullOrEmpty(saveResult.message) ? saveResult.message : "שגיאה ביצירת חשבון בענן!";
                                ShowToast(errMsg, true);
                            }
                        }
                        else
                        {
                            ShowToast("שגיאה ביצירת חשבון בענן!", true);
                        }
                    }
                }
            }
            catch
            {
                if (_security.TryLoadLocalVault(email, password, out bool pendingSync, out string serverUpdatedAt))
                {
                    _currentPasswordHash = HashPassword(password);
                    _currentServerUpdatedAt = serverUpdatedAt;
                    ShowToast(
                        pendingSync
                            ? "אין חיבור לענן. הכספת המקומית נפתחה ויש שינויים שממתינים לסנכרון."
                            : "אין חיבור לענן. הכספת המקומית נפתחה בהצלחה.",
                        false);
                    LockPassword.Password = "";
                    ShowScreen("Dashboard");
                    SwitchTab("accounts");
                    UpdateSyncBadgeStatus();
                    return;
                }

                ShowToast("אין חיבור לענן ואין כספת מקומית זמינה במחשב זה.", true);
            }
        }

        private async Task UnlockOfflineAsync(string email, string password)
        {
            if (_security.TryLoadLocalVault(email, password, out bool pendingSync, out string serverUpdatedAt))
            {
                _currentPasswordHash = HashPassword(password);
                _currentServerUpdatedAt = serverUpdatedAt;
                ShowToast("הכספת המקומית נפתחה במצב אופליין. הנתונים נשמרים במחשב זה בלבד.", false);
                LockPassword.Password = "";
                ShowScreen("Dashboard");
                SwitchTab("accounts");
                UpdateSyncBadgeStatus();
                return;
            }

            // אין כספת מקומית לאימייל זה — מציע ליצור כספת מקומית חדשה (ללא שום קשר לשרת)
            bool createLocal = ShowCustomDialog(
                "יצירת כספת מקומית",
                $"לא נמצאה כספת מקומית עבור {email} במחשב זה.\n\nבמצב אופליין הכספת נשמרת אך ורק במחשב זה ואינה מסונכרנת לשום שרת.\n\nהאם ליצור כספת מקומית חדשה?",
                true,
                "📴");
            if (!createLocal) return;

            string confirmPassword = AskUserPasswordCustomDialog("אימות סיסמה מחדש", "אנא הקלד שוב את סיסמת המאסטר שקבעת לצורך אימות:", "צור כספת 🔑");
            if (string.IsNullOrEmpty(confirmPassword)) return;

            if (password != confirmPassword)
            {
                ShowToast("הסיסמאות אינן תואמות! תהליך יצירת הכספת בוטל.", true);
                return;
            }

            _security.InitializeNewVault(password, email);
            _currentPasswordHash = HashPassword(password);
            _security.SaveLocalVault(email, "", false);
            ShowToast("כספת מקומית חדשה נוצרה בהצלחה! 📴", false);
            LockPassword.Password = "";
            ShowScreen("Dashboard");
            SwitchTab("accounts");
            UpdateSyncBadgeStatus();
        }

        private async void RequestRecovery_Click(object sender, RoutedEventArgs e)
        {
            if (_security.IsOfflineMode)
            {
                ShowCustomDialog("מצב אופליין", "שליחת קישור שחזור במייל אינה זמינה במצב אופליין, מכיוון שהתוכנה אינה מתקשרת עם השרת.\n\nמומלץ לייצא גיבוי מוצפן מההגדרות כדי לא לאבד את הגישה לכספת.", false, "📴");
                return;
            }

            string email = LockEmail.Text.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(email) || !email.Contains("@"))
            {
                ShowToast("הזן תחילה כתובת אימייל תקינה.", true);
                return;
            }

            try
            {
                ShowToast("שולח קישור שחזור למייל... נא להמתין", false);
                var payload = new { action = "begin_recovery", email = email };
                string json = JsonSerializer.Serialize(payload);
                using var content = new StringContent(json, Encoding.UTF8, "application/json");
                HttpResponseMessage response = await _httpClient.PostAsync(DeveloperScriptUrl, content);
                string responseString = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<GetVaultResult>(responseString);

                if (response.IsSuccessStatusCode && result != null && result.success)
                {
                    ShowToast("אם החשבון מוגדר לשחזור, נשלח אליו קישור במייל.", false);
                }
                else
                {
                    ShowToast(result != null && !string.IsNullOrEmpty(result.message) ? result.message : "שליחת קישור השחזור נכשלה.", true);
                }
            }
            catch
            {
                ShowToast("לא ניתן לשלוח קישור שחזור ללא חיבור תקין.", true);
            }
        }

        private void ForgotPassword_Click(object sender, RoutedEventArgs e)
        {
            ShowCustomDialog("מידע על אבטחה ושחזור", "הכספת מוצפנת בצד הלקוח. שחזור מתבצע באמצעות קישור חד-פעמי ומפתח שחזור, ללא שליחת סיסמת המאסטר הישנה במייל.", false, "🔒");
        }

        // ----------------------------------------------------
        // Dashboard Tab Switchers
        // ----------------------------------------------------
        private void TabAccounts_Click(object sender, RoutedEventArgs e) => SwitchTab("accounts");
        private void TabGuide_Click(object sender, RoutedEventArgs e) => SwitchTab("guide");
        private void TabSettings_Click(object sender, RoutedEventArgs e) => SwitchTab("settings");

        private void LockApp_Click(object sender, RoutedEventArgs e)
        {
            _security.Lock();
            _accountViewModels.Clear();
            ShowScreen("Lock");
            ShowToast("האפליקציה ננעלה בהצלחה.", false);
        }

        // ----------------------------------------------------
        // Accounts View Logic (Display & Timers)
        // ----------------------------------------------------
        private void LoadAccountsList()
        {
            _accountViewModels.Clear();
            var accounts = _security.GetAccounts();
            string filter = SearchInput.Text.Trim().ToLower();

            foreach (var acc in accounts)
            {
                if (string.IsNullOrEmpty(filter) ||
                    acc.name.ToLower().Contains(filter) ||
                    (!string.IsNullOrEmpty(acc.email) && acc.email.ToLower().Contains(filter)) ||
                    (!string.IsNullOrEmpty(acc.notes) && acc.notes.ToLower().Contains(filter)))
                {
                    var vm = new AccountViewModel(acc);
                    _accountViewModels.Add(vm);
                }
            }

            UpdateAccountsCount();
            UpdateCodesDisplay();
        }

        private void UpdateAccountsCount()
        {
            AccountsCountTitle.Text = $"חשבונות פעילים ({_accountViewModels.Count})";
            EmptyStatePanel.Visibility = _accountViewModels.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void TotpTimer_Tick(object? sender, EventArgs e)
        {
            if (_currentTab == "accounts" && DashboardScreen.Visibility == Visibility.Visible)
            {
                UpdateCodesDisplay();
            }
        }

        private void UpdateCodesDisplay()
        {
            long epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            int remainingSeconds = (int)(30 - (epoch % 30));
            
            // Dash circumference calculations
            // Radius=15, Perimeter = 2 * PI * 15 = 94.24. Thickness = 3.5 -> circumference in dash units is 94.24 / 3.5 = 26.92
            const double maxDash = 26.92; 
            double offset = maxDash * (1.0 - ((double)remainingSeconds / 30.0));

            // Select color based on timer
            Brush timerColor = Brushes.Green;
            if (remainingSeconds <= 15 && remainingSeconds > 5)
            {
                timerColor = new SolidColorBrush(Color.FromRgb(245, 158, 11)); // Warning orange
            }
            else if (remainingSeconds <= 5)
            {
                timerColor = new SolidColorBrush(Color.FromRgb(239, 68, 68)); // Danger red
            }

            foreach (var vm in _accountViewModels)
            {
                // Generate current TOTP code
                string rawCode = TotpGenerator.GenerateTotp(vm.Account.secret);
                string formattedCode = rawCode.Length == 6 ? $"{rawCode.Substring(0, 3)} {rawCode.Substring(3, 3)}" : rawCode;
                
                vm.Code = formattedCode;
                vm.StrokeDashOffset = offset;
                vm.TimerText = remainingSeconds.ToString();
                vm.TimerBrush = timerColor;
            }
        }

        private void SearchInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            LoadAccountsList();
        }

        private void OtpRow_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border border && border.Tag is string id)
            {
                var vm = _accountViewModels.FirstOrDefault(x => x.id == id);
                if (vm != null)
                {
                    string rawCode = TotpGenerator.GenerateTotp(vm.Account.secret).Replace(" ", "");
                    if (rawCode == "שגיאה")
                    {
                        ShowToast("מפתח סודי לא תקין!", true);
                        return;
                    }
                    Clipboard.SetText(rawCode);
                    ShowToast("קוד האימות הועתק ללוח! 📋", false);
                }
            }
        }

        private void ToggleDetails_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string id)
            {
                var vm = _accountViewModels.FirstOrDefault(x => x.id == id);
                if (vm != null)
                {
                    vm.IsExpanded = !vm.IsExpanded;
                    btn.Content = vm.IsExpanded ? "הערות וקודי גיבוי 🔼" : "הערות וקודי גיבוי 🔽";
                }
            }
        }

        // ----------------------------------------------------
        // Backup Codes & Actions inside Account Card
        // ----------------------------------------------------
        private void ToggleBackupCodeUsed_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is BackupCode codeObj)
            {
                codeObj.used = !codeObj.used;
                
                // Force update on UI: since BackupCode list item inside the card doesn't implement PropertyChanged,
                // we save and reload the list to refresh all visual triggers.
                var accounts = _security.GetAccounts();
                _security.SaveAccounts(accounts);
                LoadAccountsList();
                _ = SyncVaultToCloudAsync();
            }
        }

        private void CopyBackupCode_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is BackupCode codeObj)
            {
                Clipboard.SetText(codeObj.code.Replace(" ", ""));
                ShowToast("קוד הגיבוי הועתק! 📋", false);
            }
        }

        // ----------------------------------------------------
        // Add/Edit Account Modal
        // ----------------------------------------------------
        private void AddAccountButton_Click(object sender, RoutedEventArgs e)
        {
            ModalTitle.Text = "הוספת חשבון חדש";
            ModalAccName.Text = "";
            ModalAccEmail.Text = "";
            ModalAccSecret.Text = "";
            ModalAccNotes.Text = "";
            
            // Reset backup code inputs
            for (int i = 1; i <= 10; i++)
            {
                var box = (TextBox)FindName($"ModalCode{i}");
                if (box != null) box.Text = "";
            }

            _editingAccount = null;
            ResetModalBackupPanel();
            ShowModalGuide("Welcome");
            SaveAccountSubmitBtn.Content = "שמור חשבון ✨";
            AccountModalOverlay.Visibility = Visibility.Visible;
        }

        private void EditAccount_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string id)
            {
                var accs = _security.GetAccounts();
                _editingAccount = accs.FirstOrDefault(x => x.id == id);
                
                if (_editingAccount != null)
                {
                    ModalTitle.Text = "עריכת חשבון";
                    ModalAccName.Text = _editingAccount.name;
                    ModalAccEmail.Text = _editingAccount.email;
                    ModalAccSecret.Text = _editingAccount.secret;
                    ModalAccNotes.Text = _editingAccount.notes;

                    // Fill backup codes
                    bool hasCodes = false;
                    for (int i = 1; i <= 10; i++)
                    {
                        var box = (TextBox)FindName($"ModalCode{i}");
                        if (box != null)
                        {
                            if (_editingAccount.backupCodes != null && _editingAccount.backupCodes.Count >= i && _editingAccount.backupCodes[i-1] != null)
                            {
                                box.Text = _editingAccount.backupCodes[i-1].code;
                                if (!string.IsNullOrEmpty(box.Text)) hasCodes = true;
                            }
                            else
                            {
                                box.Text = "";
                            }
                        }
                    }

                    if (hasCodes)
                    {
                        _backupCodesExpanded = true;
                        ModalBackupCodesPanel.Visibility = Visibility.Visible;
                        ToggleModalBackupBtn.Content = "➖ הסתרת קודי גיבוי לחשבון (אופציונלי)";
                    }
                    else
                    {
                        ResetModalBackupPanel();
                    }

                    ShowModalGuide("Welcome");
                    SaveAccountSubmitBtn.Content = "עדכן שינויים 💾";
                    AccountModalOverlay.Visibility = Visibility.Visible;
                }
            }
        }

        private void CloseModal_Click(object sender, RoutedEventArgs e)
        {
            AccountModalOverlay.Visibility = Visibility.Collapsed;
        }

        private void ToggleModalBackup_Click(object sender, RoutedEventArgs e)
        {
            _backupCodesExpanded = !_backupCodesExpanded;
            if (_backupCodesExpanded)
            {
                ModalBackupCodesPanel.Visibility = Visibility.Visible;
                ToggleModalBackupBtn.Content = "➖ הסתרת קודי גיבוי לחשבון (אופציונלי)";
            }
            else
            {
                ModalBackupCodesPanel.Visibility = Visibility.Collapsed;
                ToggleModalBackupBtn.Content = "➕ הוספת 10 קודי גיבוי לחשבון (אופציונלי)";
            }
        }

        private void ResetModalBackupPanel()
        {
            _backupCodesExpanded = false;
            ModalBackupCodesPanel.Visibility = Visibility.Collapsed;
            ToggleModalBackupBtn.Content = "➕ הוספת 10 קודי גיבוי לחשבון (אופציונלי)";
        }

        private void SaveAccountSubmit_Click(object sender, RoutedEventArgs e)
        {
            string name = ModalAccName.Text.Trim();
            string email = ModalAccEmail.Text.Trim();
            string secret = ModalAccSecret.Text.Trim().Replace(" ", "").ToUpper();
            string notes = ModalAccNotes.Text.Trim();

            if (string.IsNullOrEmpty(name))
            {
                ShowToast("שם השירות / אתר הוא שדה חובה!", true);
                return;
            }

            // Verify Base32 Secret Key
            string checkTotp = TotpGenerator.GenerateTotp(secret);
            if (checkTotp == "שגיאה")
            {
                ShowToast("מפתח סודי לא תקין! המפתח חייב להכיל רק אותיות A-Z ומספרים 2-7.", true);
                return;
            }

            // Collect backup codes
            List<BackupCode> codesList = new List<BackupCode>();
            for (int i = 1; i <= 10; i++)
            {
                var box = (TextBox)FindName($"ModalCode{i}");
                string codeText = box != null ? box.Text.Trim() : "";

                bool oldUsed = false;
                if (_editingAccount != null && _editingAccount.backupCodes != null && _editingAccount.backupCodes.Count >= i)
                {
                    // Preserve "used" state if the code text hasn't changed
                    if (_editingAccount.backupCodes[i-1].code == codeText)
                    {
                        oldUsed = _editingAccount.backupCodes[i-1].used;
                    }
                }
                codesList.Add(new BackupCode { code = codeText, used = oldUsed });
            }

            var accounts = _security.GetAccounts();

            if (_editingAccount != null)
            {
                // Update existing account
                var target = accounts.FirstOrDefault(x => x.id == _editingAccount.id);
                if (target != null)
                {
                    target.name = name;
                    target.email = email;
                    target.secret = secret;
                    target.notes = notes;
                    target.backupCodes = codesList;
                }
                ShowToast("החשבון עודכן בהצלחה!", false);
            }
            else
            {
                // Create new account
                var newAcc = new GoogleAccount
                {
                    id = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(),
                    name = name,
                    email = email,
                    secret = secret,
                    notes = notes,
                    backupCodes = codesList
                };
                accounts.Add(newAcc);
                ShowToast("חשבון חדש נוסף למערכת!", false);
            }

            _security.SaveAccounts(accounts);
            AccountModalOverlay.Visibility = Visibility.Collapsed;
            LoadAccountsList();
            _ = SyncVaultToCloudAsync();
        }

        private void DeleteAccount_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string id)
            {
                var accounts = _security.GetAccounts();
                var acc = accounts.FirstOrDefault(x => x.id == id);
                if (acc != null)
                {
                    bool result = ShowCustomDialog("מחיקת חשבון", $"האם אתה בטוח שברצונך למחוק לחלוטין את החשבון \"{acc.name}\"?", true, "⚠️");
                    
                    if (result)
                    {
                        accounts.Remove(acc);
                        _security.SaveAccounts(accounts);
                        LoadAccountsList();
                        _ = SyncVaultToCloudAsync();
                    }
                }
            }
        }

        private void UploadBackupCodesFile_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                Title = "טען קובץ קודי גיבוי"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    string text = File.ReadAllText(openFileDialog.FileName);
                    
                    // Regex matching 8 digit codes, allowing spaces in middle (e.g. 1234 5678 or 12345678)
                    var regex = new Regex(@"\b\d{4}\s?\d{4}\b|\b\d{8}\b");
                    var matches = regex.Matches(text);

                    if (matches.Count == 0)
                    {
                        ShowToast("לא נמצאו קודי גיבוי תקינים בקובץ הטקסט!", true);
                        return;
                    }

                    // Open backup panel if closed
                    _backupCodesExpanded = true;
                    ModalBackupCodesPanel.Visibility = Visibility.Visible;
                    ToggleModalBackupBtn.Content = "➖ הסתרת קודי גיבוי לחשבון (אופציונלי)";

                    // Populate fields
                    int fillCount = Math.Min(matches.Count, 10);
                    for (int i = 1; i <= 10; i++)
                    {
                        var box = (TextBox)FindName($"ModalCode{i}");
                        if (box != null)
                        {
                            if (i <= fillCount)
                            {
                                box.Text = matches[i - 1].Value.Replace(" ", "");
                            }
                            else
                            {
                                box.Text = "";
                            }
                        }
                    }

                    ShowToast($"נטענו בהצלחה {fillCount} קודי גיבוי מתוך הקובץ!", false);
                }
                catch (Exception ex)
                {
                    ShowToast($"שגיאה בקריאת הקובץ: {ex.Message}", true);
                }
            }
        }

        // ----------------------------------------------------
        // Dynamic Help Column Logic in Modal Form
        // ----------------------------------------------------
        private void ShowModalGuide(string stepName)
        {
            ModalGuide_Welcome.Visibility = stepName == "Welcome" ? Visibility.Visible : Visibility.Collapsed;
            ModalGuide_Name.Visibility = stepName == "Name" ? Visibility.Visible : Visibility.Collapsed;
            ModalGuide_Secret.Visibility = stepName == "Secret" ? Visibility.Visible : Visibility.Collapsed;
            ModalGuide_Notes.Visibility = stepName == "Notes" ? Visibility.Visible : Visibility.Collapsed;
            ModalGuide_Backup.Visibility = stepName == "Backup" ? Visibility.Visible : Visibility.Collapsed;
        }

        private void ModalAccName_GotFocus(object sender, RoutedEventArgs e) => ShowModalGuide("Name");
        private void ModalAccSecret_GotFocus(object sender, RoutedEventArgs e)
        {
            ShowModalGuide("Secret");
            SecretGuideTabControl.SelectedIndex = 4; // Focus on "לא מצליח" step
        }
        private void ModalAccNotes_GotFocus(object sender, RoutedEventArgs e) => ShowModalGuide("Notes");
        private void ModalAccBackup_GotFocus(object sender, RoutedEventArgs e) => ShowModalGuide("Backup");

        // ----------------------------------------------------
        // Guide View Handlers
        // ----------------------------------------------------
        private void OpenTwoStepUrl_Click(object sender, RoutedEventArgs e)
        {
            OpenUrl("https://g.co/2sv");
        }

        private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            OpenUrl(e.Uri.AbsoluteUri);
            e.Handled = true;
        }

        private void OpenUrl(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                ShowCustomDialog("שגיאה", $"לא ניתן לפתוח את הקישור: {ex.Message}", false, "❌");
            }
        }

        // ----------------------------------------------------
        // Settings View Handlers
        // ----------------------------------------------------
        private void LoadSettingsData()
        {
            SettingsEmail.Text = _security.GetRecoveryEmail();
            OldPassword.Password = "";
            NewPassword.Password = "";
            SyncModeRadio.IsChecked = !_security.IsOfflineMode;
            OfflineModeRadio.IsChecked = _security.IsOfflineMode;
        }

        private void SyncModeRadio_Checked(object sender, RoutedEventArgs e)
        {
            if (SyncModeRadio.IsChecked == true)
            {
                SetSyncMode(false);
            }
        }

        private void OfflineModeRadio_Checked(object sender, RoutedEventArgs e)
        {
            if (OfflineModeRadio.IsChecked == true)
            {
                SetSyncMode(true);
            }
        }

        private void SetSyncMode(bool offline)
        {
            if (_security.IsOfflineMode == offline) return;

            if (offline)
            {
                bool confirm = ShowCustomDialog(
                    "מעבר למצב אופליין מלא",
                    "במצב אופליין התוכנה לא תיצור שום קשר עם השרת:\n\n" +
                    "• הכספת תישמר במחשב זה בלבד\n" +
                    "• לא יתבצע גיבוי בענן\n" +
                    "• שחזור סיסמה במייל לא יהיה זמין\n\n" +
                    "להמשיך?",
                    true,
                    "📴");
                if (!confirm)
                {
                    // ביטול — מחזיר את הבחירה למצב הקודם
                    SyncModeRadio.IsChecked = true;
                    return;
                }
            }

            _security.SetOfflineMode(offline);
            UpdateLockScreenForMode();
            UpdateSyncBadgeStatus();
            ShowToast(offline
                ? "מצב אופליין הופעל — הנתונים נשמרים במחשב זה בלבד."
                : "מצב סנכרון הופעל — התוכנה תסנכרן שוב עם השרת.", false);

            // בחזרה למצב מסונכרן — נסה להעלות שינויים מקומיים שהמתינו
            if (!offline && _security.IsUnlocked())
            {
                _ = SyncVaultToCloudAsync();
            }
        }

        private async void SaveSettingsEmail_Click(object sender, RoutedEventArgs e)
        {
            string newEmail = SettingsEmail.Text.Trim().ToLower();
            if (string.IsNullOrEmpty(newEmail) || !newEmail.Contains("@"))
            {
                ShowToast("נא להזין כתובת אימייל תקינה!", true);
                return;
            }

            string oldEmail = _security.GetRecoveryEmail();
            if (newEmail == oldEmail)
            {
                ShowToast("כתובת האימייל זהה לנוכחית.", false);
                return;
            }

            string whereSaved = _security.IsOfflineMode
                ? "הכספת תישמר מקומית תחת האימייל החדש."
                : "הכספת תישמר בענן תחת האימייל החדש.";
            var confirm = MessageBox.Show($"האם ברצונך להעביר את הכספת לכתובת האימייל החדשה: {newEmail}?\n\n{whereSaved}",
                                          "שינוי אימייל כספת",
                                          MessageBoxButton.YesNo,
                                          MessageBoxImage.Question,
                                          MessageBoxResult.No,
                                          MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign);

            if (confirm == MessageBoxResult.Yes)
            {
                _security.SetRecoveryEmail(newEmail);
                bool success = await SyncVaultToCloudAsync();
                if (success)
                {
                    // מסיר את מטמון הכספת המקומית של האימייל הישן כדי שלא תישאר גישה דרך כתובת ישנה
                    _security.DeleteLocalVault(oldEmail);
                    ShowToast("הכספת הועברה בהצלחה לאימייל החדש!", false);
                }
                else
                {
                    // Revert on failure
                    _security.SetRecoveryEmail(oldEmail);
                    ShowToast("העברת הכספת נכשלה. שוחזר האימייל הקודם.", true);
                }
            }
        }

        private async void ChangeMasterPassword_Click(object sender, RoutedEventArgs e)
        {
            string oldP = OldPassword.Password;
            string newP = NewPassword.Password;

            if (string.IsNullOrEmpty(oldP) || string.IsNullOrEmpty(newP))
            {
                ShowToast("נא למלא את כל השדות!", true);
                return;
            }

            if (newP.Length < 4)
            {
                ShowToast("הסיסמה החדשה חייבת להיות באורך 4 תווים לפחות!", true);
                return;
            }

            if (_security.ChangePassword(oldP, newP))
            {
                OldPassword.Password = "";
                NewPassword.Password = "";
                
                // Update cached hash
                _currentPasswordHash = HashPassword(newP);
                
                ShowToast("סיסמת המאסטר שונתה בהצלחה!", false);

                // Sync the re-encrypted vault and the new password hash to the cloud!
                await SyncVaultToCloudAsync();
            }
            else
            {
                ShowToast("הסיסמה הנוכחית אינה נכונה!", true);
            }
        }

        private void ExportBackup_Click(object sender, RoutedEventArgs e)
        {
            var saveFileDialog = new SaveFileDialog
            {
                Filter = "JSON Files (*.json)|*.json",
                FileName = $"Master_Authenticator_Backup_{DateTime.Now:yyyy-MM-dd}.json",
                Title = "ייצוא גיבוי מוצפן"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    string json = _security.ExportVault();
                    File.WriteAllText(saveFileDialog.FileName, json);
                    ShowToast("קובץ הגיבוי המוצפן נוצר והורד בהצלחה! 📥", false);
                }
                catch (Exception ex)
                {
                    ShowToast($"שגיאה בייצוא קובץ הגיבוי: {ex.Message}", true);
                }
            }
        }

        private async void ImportBackup_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "JSON Files (*.json)|*.json",
                Title = "ייבוא קובץ גיבוי מוצפן"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                bool result = ShowCustomDialog("ייבוא גיבוי", "ייבוא קובץ זה יחליף לחלוטין את כל החשבונות הנוכחיים. האם להמשיך?", true, "⚠️");

                if (result)
                {
                    try
                    {
                        string json = File.ReadAllText(openFileDialog.FileName);
                        
                        // Ask for the backup file's master password
                        string backupPassword = AskUserPasswordCustomDialog("סיסמת קובץ הגיבוי", "אנא הזן את סיסמת המאסטר של קובץ הגיבוי:", "סנכרן 💾");
                        if (string.IsNullOrEmpty(backupPassword))
                        {
                            return;
                        }

                        if (_security.ImportVault(json, backupPassword))
                        {
                            // Update our session password hash to match the imported backup's password
                            _currentPasswordHash = HashPassword(backupPassword);
                            
                            // Load the imported accounts list
                            LoadAccountsList();
                            
                            ShowToast("הגיבוי יובא בהצלחה! מסנכרן לענן...", false);
                            
                            // Upload the imported vault to the cloud under the current logged-in email
                            await SyncVaultToCloudAsync();
                        }
                        else
                        {
                            ShowToast("סיסמת הגיבוי שגויה או שקובץ הגיבוי פגום!", true);
                        }
                    }
                    catch (Exception ex)
                    {
                        ShowToast($"שגיאה בייבוא קובץ הגיבוי: {ex.Message}", true);
                    }
                }
            }
        }

        private void ResetSystem_Click(object sender, RoutedEventArgs e)
        {
            bool r1 = ShowCustomDialog("אזהרה", "האם אתה בטוח שברצונך להתנתק ולמחוק את נתוני הסשן הנוכחי בזיכרון?", true, "⚠️");
            
            if (r1)
            {
                _security.Lock();
                _currentPasswordHash = "";
                _accountViewModels.Clear();
                ShowToast("התנתקת בהצלחה מהמערכת.", false);
                ShowScreen("Lock");
                LockEmail.Text = "";
                LockPassword.Password = "";
                LockEmail.Focus();
                UpdateSyncBadgeStatus();
            }
        }

        // ----------------------------------------------------
        // Sync & Badge logic
        // ----------------------------------------------------
        private async Task<bool> SyncVaultToCloudAsync()
        {
            // במצב אופליין אין שום קשר עם השרת — הכספת נשמרת מקומית בלבד
            if (_security.IsOfflineMode)
            {
                string offlineEmail = _security.GetRecoveryEmail();
                if (string.IsNullOrEmpty(offlineEmail)) return false;
                _security.SaveLocalVault(offlineEmail, _currentServerUpdatedAt, false);
                UpdateSyncBadgeStatus();
                return true;
            }

            if (DeveloperScriptUrl.Contains("YOUR_WORKERS_SUBDOMAIN"))
                return false;

            string email = _security.GetRecoveryEmail();
            if (string.IsNullOrEmpty(email)) return false;

            var recovery = _security.PrepareRecoveryMaterial();
            string vaultJson = _security.ExportVault();
            _security.SaveLocalVault(email, _currentServerUpdatedAt, true);

            if (!NetworkInterface.GetIsNetworkAvailable())
            {
                ShowToast("השינויים נשמרו מקומית ויועלו לענן כשהחיבור יחזור.", false);
                UpdateSyncBadgeStatus();
                return false;
            }

            try
            {
                var payload = new
                {
                    action = "save_vault",
                    email = email,
                    password = _currentPasswordHash,
                    vault = vaultJson,
                    recoveryKey = recovery.recoveryKey,
                    recoveryPackage = recovery.recoveryPackage,
                    clientVersion = "secure-v1"
                };
                string json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                HttpResponseMessage response = await _httpClient.PostAsync(DeveloperScriptUrl, content);
                if (response.IsSuccessStatusCode)
                {
                    string responseString = await response.Content.ReadAsStringAsync();
                    var result = JsonSerializer.Deserialize<GetVaultResult>(responseString);
                    if (result != null && result.success)
                    {
                        _currentServerUpdatedAt = result.updatedAt ?? DateTime.UtcNow.ToString("O");
                        _security.SaveLocalVault(email, _currentServerUpdatedAt, false);
                        ShowToast("השינויים סונכרנו בהצלחה בענן! ☁️", false);
                        UpdateSyncBadgeStatus();
                        return true;
                    }
                    else
                    {
                        string errMsg = result != null && !string.IsNullOrEmpty(result.message) ? result.message : "שגיאה בסנכרון השינויים לענן!";
                        ShowToast(errMsg, true);
                        return false;
                    }
                }
                else
                {
                    ShowToast("שגיאה בסנכרון השינויים לענן!", true);
                    return false;
                }
            }
            catch
            {
                _security.SaveLocalVault(email, _currentServerUpdatedAt, true);
                ShowToast("השינויים נשמרו מקומית; הסנכרון ינסה שוב כשהחיבור יחזור.", false);
                return false;
            }
        }

        private void UpdateSyncBadgeStatus()
        {
            string email = _security.GetRecoveryEmail();
            if (_security.IsOfflineMode && _security.IsUnlocked())
            {
                SyncBadge.Background = new SolidColorBrush(Color.FromArgb(21, 139, 92, 246));
                SyncBadge.BorderBrush = new SolidColorBrush(Color.FromArgb(32, 139, 92, 246));
                SyncBadgeText.Text = "מצב אופליין — נתונים מקומיים בלבד 📴";
                SyncBadgeText.Foreground = new SolidColorBrush(Color.FromRgb(139, 92, 246));
            }
            else if (_security.IsUnlocked() && _security.HasPendingLocalSync(email))
            {
                SyncBadge.Background = new SolidColorBrush(Color.FromArgb(21, 245, 158, 11));
                SyncBadge.BorderBrush = new SolidColorBrush(Color.FromArgb(32, 245, 158, 11));
                SyncBadgeText.Text = "נשמר מקומית — ממתין לסנכרון ⏳";
                SyncBadgeText.Foreground = new SolidColorBrush(Color.FromRgb(245, 158, 11));
            }
            else if (_security.IsUnlocked() && !NetworkInterface.GetIsNetworkAvailable())
            {
                SyncBadge.Background = new SolidColorBrush(Color.FromArgb(21, 139, 92, 246));
                SyncBadge.BorderBrush = new SolidColorBrush(Color.FromArgb(32, 139, 92, 246));
                SyncBadgeText.Text = "מצב אופליין — הכספת מקומית בלבד 📴";
                SyncBadgeText.Foreground = new SolidColorBrush(Color.FromRgb(139, 92, 246));
            }
            else if (_security.IsUnlocked())
            {
                SyncBadge.Background = new SolidColorBrush(Color.FromArgb(21, 16, 185, 129)); // Green opacity
                SyncBadge.BorderBrush = new SolidColorBrush(Color.FromArgb(32, 16, 185, 129));
                SyncBadgeText.Text = "מחובר ומסונכרן לענן ☁️";
                SyncBadgeText.Foreground = new SolidColorBrush(Color.FromRgb(16, 185, 129));
            }
            else
            {
                SyncBadge.Background = new SolidColorBrush(Color.FromArgb(21, 139, 92, 246)); // Purple opacity
                SyncBadge.BorderBrush = new SolidColorBrush(Color.FromArgb(32, 139, 92, 246));
                SyncBadgeText.Text = "הכספת נעולה 🔒";
                SyncBadgeText.Foreground = new SolidColorBrush(Color.FromRgb(139, 92, 246));
            }
        }

        // ----------------------------------------------------
        // Popup / Dialog Helpers
        // ----------------------------------------------------
        private bool ShowCustomDialog(string title, string message, bool isYesNo = true, string icon = "❓")
        {
            var dialog = new Window
            {
                Title = title,
                Width = 420,
                Height = 220,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                WindowStyle = WindowStyle.None,
                AllowsTransparency = true,
                Background = Brushes.Transparent,
                FlowDirection = FlowDirection.RightToLeft,
                ShowInTaskbar = false
            };

            var border = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(15, 23, 42)), // Slate 900
                BorderBrush = new SolidColorBrush(Color.FromRgb(139, 92, 246)), // Purple 500
                BorderThickness = new Thickness(1.5),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(20)
            };

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Title
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Content
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Buttons

            var titleBar = new Grid { Margin = new Thickness(0, 0, 0, 15) };
            titleBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            titleBar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleText = new TextBlock
            {
                Text = title,
                Foreground = Brushes.White,
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(titleText, 0);
            titleBar.Children.Add(titleText);

            var closeWindowBtn = new Button
            {
                Content = "✕",
                Foreground = new SolidColorBrush(Color.FromRgb(148, 163, 184)), // Slate 400
                Background = Brushes.Transparent,
                BorderBrush = Brushes.Transparent,
                Cursor = Cursors.Hand,
                FontSize = 14,
                Width = 24,
                Height = 24,
                VerticalAlignment = VerticalAlignment.Center
            };
            closeWindowBtn.Click += (s, e) => { dialog.DialogResult = false; dialog.Close(); };
            Grid.SetColumn(closeWindowBtn, 1);
            titleBar.Children.Add(closeWindowBtn);

            Grid.SetRow(titleBar, 0);
            mainGrid.Children.Add(titleBar);

            var contentGrid = new Grid { Margin = new Thickness(0, 0, 0, 20) };
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(45) });
            contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var iconBlock = new TextBlock
            {
                Text = icon,
                FontSize = 28,
                VerticalAlignment = VerticalAlignment.Top,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            };
            Grid.SetColumn(iconBlock, 0);
            contentGrid.Children.Add(iconBlock);

            var messageScroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                MaxHeight = 100
            };
            var messageText = new TextBlock
            {
                Text = message,
                Foreground = new SolidColorBrush(Color.FromRgb(226, 232, 240)), // Slate 200
                FontSize = 13,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 18
            };
            messageScroll.Content = messageText;
            Grid.SetColumn(messageScroll, 1);
            contentGrid.Children.Add(messageScroll);

            Grid.SetRow(contentGrid, 1);
            mainGrid.Children.Add(contentGrid);

            var buttonsPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Left
            };

            bool dialogResult = false;

            if (isYesNo)
            {
                var yesBtn = new Button
                {
                    Content = "כן 👍",
                    Height = 32,
                    MinWidth = 80,
                    Margin = new Thickness(0, 0, 10, 0),
                    Background = new SolidColorBrush(Color.FromRgb(139, 92, 246)), // Purple 500
                    Foreground = Brushes.White,
                    FontWeight = FontWeights.Bold,
                    BorderThickness = new Thickness(0),
                    Cursor = Cursors.Hand
                };
                var yesTemplate = new ControlTemplate(typeof(Button));
                var yesBorder = new FrameworkElementFactory(typeof(Border));
                yesBorder.SetValue(Border.BackgroundProperty, new SolidColorBrush(Color.FromRgb(139, 92, 246)));
                yesBorder.SetValue(Border.CornerRadiusProperty, new CornerRadius(6));
                var yesPresenter = new FrameworkElementFactory(typeof(ContentPresenter));
                yesPresenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
                yesPresenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
                yesBorder.AppendChild(yesPresenter);
                yesTemplate.VisualTree = yesBorder;
                yesBtn.Template = yesTemplate;

                yesBtn.Click += (s, e) =>
                {
                    dialogResult = true;
                    dialog.DialogResult = true;
                    dialog.Close();
                };
                buttonsPanel.Children.Add(yesBtn);

                var noBtn = new Button
                {
                    Content = "לא",
                    Height = 32,
                    MinWidth = 80,
                    Background = new SolidColorBrush(Color.FromRgb(71, 85, 105)), // Slate 600
                    Foreground = Brushes.White,
                    BorderThickness = new Thickness(0),
                    Cursor = Cursors.Hand
                };
                var noTemplate = new ControlTemplate(typeof(Button));
                var noBorder = new FrameworkElementFactory(typeof(Border));
                noBorder.SetValue(Border.BackgroundProperty, new SolidColorBrush(Color.FromRgb(71, 85, 105)));
                noBorder.SetValue(Border.CornerRadiusProperty, new CornerRadius(6));
                var noPresenter = new FrameworkElementFactory(typeof(ContentPresenter));
                noPresenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
                noPresenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
                noBorder.AppendChild(noPresenter);
                noTemplate.VisualTree = noBorder;
                noBtn.Template = noTemplate;

                noBtn.Click += (s, e) =>
                {
                    dialogResult = false;
                    dialog.DialogResult = false;
                    dialog.Close();
                };
                buttonsPanel.Children.Add(noBtn);
            }
            else
            {
                var okBtn = new Button
                {
                    Content = "הבנתי 👍",
                    Height = 32,
                    MinWidth = 90,
                    Background = new SolidColorBrush(Color.FromRgb(139, 92, 246)), // Purple 500
                    Foreground = Brushes.White,
                    FontWeight = FontWeights.Bold,
                    BorderThickness = new Thickness(0),
                    Cursor = Cursors.Hand
                };
                var okTemplate = new ControlTemplate(typeof(Button));
                var okBorder = new FrameworkElementFactory(typeof(Border));
                okBorder.SetValue(Border.BackgroundProperty, new SolidColorBrush(Color.FromRgb(139, 92, 246)));
                okBorder.SetValue(Border.CornerRadiusProperty, new CornerRadius(6));
                var okPresenter = new FrameworkElementFactory(typeof(ContentPresenter));
                okPresenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
                okPresenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
                okBorder.AppendChild(okPresenter);
                okTemplate.VisualTree = okBorder;
                okBtn.Template = okTemplate;

                okBtn.Click += (s, e) =>
                {
                    dialogResult = true;
                    dialog.DialogResult = true;
                    dialog.Close();
                };
                buttonsPanel.Children.Add(okBtn);
            }

            Grid.SetRow(buttonsPanel, 2);
            mainGrid.Children.Add(buttonsPanel);

            border.Child = mainGrid;
            dialog.Content = border;

            titleBar.MouseLeftButtonDown += (s, e) => { if (e.LeftButton == MouseButtonState.Pressed) dialog.DragMove(); };

            if (message.Length > 200)
            {
                dialog.Height = 270;
                messageScroll.MaxHeight = 150;
            }

            dialog.ShowDialog();
            return dialogResult;
        }

        private string AskUserPasswordCustomDialog(string title, string instruction, string buttonText = "אישור 🔑")
        {
            var dialog = new Window
            {
                Title = title,
                Width = 380,
                Height = 190,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                WindowStyle = WindowStyle.None,
                AllowsTransparency = true,
                Background = Brushes.Transparent,
                FlowDirection = FlowDirection.RightToLeft,
                ShowInTaskbar = false
            };

            var border = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(15, 23, 42)), // Slate 900
                BorderBrush = new SolidColorBrush(Color.FromRgb(139, 92, 246)), // Purple 500
                BorderThickness = new Thickness(1.5),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(20)
            };

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Title
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Input
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Buttons

            var titleBar = new Grid { Margin = new Thickness(0, 0, 0, 12) };
            titleBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            titleBar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleText = new TextBlock
            {
                Text = title,
                Foreground = Brushes.White,
                FontSize = 15,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(titleText, 0);
            titleBar.Children.Add(titleText);

            var closeBtn = new Button
            {
                Content = "✕",
                Foreground = new SolidColorBrush(Color.FromRgb(148, 163, 184)), // Slate 400
                Background = Brushes.Transparent,
                BorderBrush = Brushes.Transparent,
                Cursor = Cursors.Hand,
                FontSize = 13,
                Width = 24,
                Height = 24,
                VerticalAlignment = VerticalAlignment.Center
            };
            closeBtn.Click += (s, e) => dialog.Close();
            Grid.SetColumn(closeBtn, 1);
            titleBar.Children.Add(closeBtn);

            Grid.SetRow(titleBar, 0);
            mainGrid.Children.Add(titleBar);

            var inputStack = new StackPanel { Margin = new Thickness(0, 0, 0, 15) };
            var instructionText = new TextBlock
            {
                Text = instruction,
                Foreground = new SolidColorBrush(Color.FromRgb(226, 232, 240)), // Slate 200
                FontSize = 13,
                Margin = new Thickness(0, 0, 0, 8),
                TextWrapping = TextWrapping.Wrap
            };
            inputStack.Children.Add(instructionText);

            var passBox = new PasswordBox
            {
                Height = 32,
                Background = new SolidColorBrush(Color.FromRgb(30, 41, 59)), // Slate 800
                Foreground = Brushes.White,
                BorderBrush = new SolidColorBrush(Color.FromRgb(139, 92, 246)), // Purple 500
                BorderThickness = new Thickness(1.5),
                Padding = new Thickness(8, 2, 8, 2),
                VerticalContentAlignment = VerticalAlignment.Center
            };
            inputStack.Children.Add(passBox);

            Grid.SetRow(inputStack, 1);
            mainGrid.Children.Add(inputStack);

            var buttonsGrid = new Grid();
            buttonsGrid.ColumnDefinitions.Add(new ColumnDefinition());
            buttonsGrid.ColumnDefinitions.Add(new ColumnDefinition());

            string result = "";

            var okBtn = new Button
            {
                Content = buttonText,
                IsDefault = true,
                Height = 32,
                Margin = new Thickness(0, 0, 5, 0),
                Background = new SolidColorBrush(Color.FromRgb(139, 92, 246)), // Purple 500
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };
            var okTemplate = new ControlTemplate(typeof(Button));
            var okBorder = new FrameworkElementFactory(typeof(Border));
            okBorder.SetValue(Border.BackgroundProperty, new SolidColorBrush(Color.FromRgb(139, 92, 246)));
            okBorder.SetValue(Border.CornerRadiusProperty, new CornerRadius(6));
            var okPresenter = new FrameworkElementFactory(typeof(ContentPresenter));
            okPresenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            okPresenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            okBorder.AppendChild(okPresenter);
            okTemplate.VisualTree = okBorder;
            okBtn.Template = okTemplate;

            okBtn.Click += (s, e) =>
            {
                result = passBox.Password;
                dialog.DialogResult = true;
                dialog.Close();
            };

            var cancelBtn = new Button
            {
                Content = "ביטול",
                IsCancel = true,
                Height = 32,
                Margin = new Thickness(5, 0, 0, 0),
                Background = new SolidColorBrush(Color.FromRgb(71, 85, 105)), // Slate 600
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };
            var cancelTemplate = new ControlTemplate(typeof(Button));
            var cancelBorder = new FrameworkElementFactory(typeof(Border));
            cancelBorder.SetValue(Border.BackgroundProperty, new SolidColorBrush(Color.FromRgb(71, 85, 105)));
            cancelBorder.SetValue(Border.CornerRadiusProperty, new CornerRadius(6));
            var cancelPresenter = new FrameworkElementFactory(typeof(ContentPresenter));
            cancelPresenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cancelPresenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            cancelBorder.AppendChild(cancelPresenter);
            cancelTemplate.VisualTree = cancelBorder;
            cancelBtn.Template = cancelTemplate;

            cancelBtn.Click += (s, e) => dialog.Close();

            Grid.SetColumn(okBtn, 0);
            Grid.SetColumn(cancelBtn, 1);
            buttonsGrid.Children.Add(okBtn);
            buttonsGrid.Children.Add(cancelBtn);

            Grid.SetRow(buttonsGrid, 2);
            mainGrid.Children.Add(buttonsGrid);

            border.Child = mainGrid;
            dialog.Content = border;

            titleBar.MouseLeftButtonDown += (s, e) => { if (e.LeftButton == MouseButtonState.Pressed) dialog.DragMove(); };

            dialog.Loaded += (s, e) => passBox.Focus();

            if (dialog.ShowDialog() == true)
            {
                return result;
            }
            return "";
        }

        // ----------------------------------------------------
        // Toast Notification System
        // ----------------------------------------------------
        private void ShowToast(string message, bool isError)
        {
            // We create a lightweight custom popup/toast window to avoid importing massive UI packages
            var toast = new Window
            {
                Width = 320, Height = 60, WindowStyle = WindowStyle.None, AllowsTransparency = true,
                Background = new SolidColorBrush(Color.FromArgb(240, 30, 41, 59)),
                ShowInTaskbar = false, Topmost = true, WindowStartupLocation = WindowStartupLocation.Manual,
                FlowDirection = FlowDirection.RightToLeft
            };

            var border = new Border
            {
                BorderThickness = new Thickness(0, 0, 4, 0),
                BorderBrush = isError ? new SolidColorBrush(Color.FromRgb(239, 68, 68)) : new SolidColorBrush(Color.FromRgb(16, 185, 129)),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(15, 10, 15, 10),
                Background = new SolidColorBrush(Color.FromArgb(20, 255, 255, 255))
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(30) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var icon = new TextBlock { Text = isError ? "❌" : "✅", FontSize = 16, VerticalAlignment = VerticalAlignment.Center };
            var txt = new TextBlock { Text = message, Foreground = Brushes.White, FontSize = 12, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap };
            
            Grid.SetColumn(icon, 0);
            Grid.SetColumn(txt, 1);
            grid.Children.Add(icon);
            grid.Children.Add(txt);
            border.Child = grid;
            toast.Content = border;

            // Position toast at top-center of owner window
            double ownerLeft = Left;
            double ownerTop = Top;
            double ownerWidth = Width;

            toast.Left = ownerLeft + (ownerWidth - toast.Width) / 2;
            toast.Top = ownerTop + 45;

            toast.Show();

            // Fade out and close after 3 seconds
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            timer.Tick += (s, e) => { toast.Close(); timer.Stop(); };
            timer.Start();
        }

        // Title bar drag & double-click maximize handler
        private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
            {
                if (e.ClickCount == 2)
                {
                    ToggleMaximize();
                }
                else if (e.ButtonState == MouseButtonState.Pressed)
                {
                    DragMove();
                }
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        // Window Maximize/Restore Toggle
        private void ToggleMaximize()
        {
            if (WindowState == WindowState.Maximized)
            {
                WindowState = WindowState.Normal;
                MaximizeButton.Content = "🗖";
                MainBorder.CornerRadius = new CornerRadius(16);
                MainBorder.BorderThickness = new Thickness(1.5);
            }
            else
            {
                MaxHeight = SystemParameters.WorkArea.Height;
                MaxWidth = SystemParameters.WorkArea.Width;
                WindowState = WindowState.Maximized;
                MaximizeButton.Content = "🗗";
                MainBorder.CornerRadius = new CornerRadius(0);
                MainBorder.BorderThickness = new Thickness(0);
            }
        }

        private void MaximizeButton_Click(object sender, RoutedEventArgs e)
        {
            ToggleMaximize();
        }

        // Lightbox handlers
        private void GuideImage_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is Image img)
            {
                LightboxImage.Source = img.Source;
                ImageLightboxOverlay.Visibility = Visibility.Visible;
            }
        }

        private void CloseLightbox_Click(object sender, RoutedEventArgs e)
        {
            ImageLightboxOverlay.Visibility = Visibility.Collapsed;
        }

        private void CloseLightbox_MouseClick(object sender, MouseButtonEventArgs e)
        {
            ImageLightboxOverlay.Visibility = Visibility.Collapsed;
        }

        // ----------------------------------------------------
        // QR Code Scanner Logic
        // ----------------------------------------------------
        private async void ScanQrBtn_Click(object sender, RoutedEventArgs e)
        {
            this.Visibility = Visibility.Collapsed;
            
            // Give the UI thread time to fully hide the window before capturing the screen
            await Task.Delay(300);

            try
            {
                int screenLeft = (int)SystemParameters.VirtualScreenLeft;
                int screenTop = (int)SystemParameters.VirtualScreenTop;
                int screenWidth = (int)SystemParameters.VirtualScreenWidth;
                int screenHeight = (int)SystemParameters.VirtualScreenHeight;

                using (var screenBmp = new System.Drawing.Bitmap(screenWidth, screenHeight))
                {
                    using (var g = System.Drawing.Graphics.FromImage(screenBmp))
                    {
                        g.CopyFromScreen(screenLeft, screenTop, 0, 0, screenBmp.Size);
                    }

                    var captureWindow = new QrCaptureWindow(screenBmp);
                    captureWindow.ShowDialog();

                    if (captureWindow.CroppedResult != null)
                    {
                        string? textResult = DecodeQrFromBitmap(captureWindow.CroppedResult);
                        if (!string.IsNullOrEmpty(textResult))
                        {
                            ParseAndFillOtpAuth(textResult);
                        }
                        else
                        {
                            ShowToast("לא נמצא קוד QR באזור שנבחר. ודא שהקוד מוצג בבירור.", true);
                        }

                        captureWindow.CroppedResult.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                ShowToast($"שגיאה במהלך צילום או סריקת הברקוד: {ex.Message}", true);
            }
            finally
            {
                this.Visibility = Visibility.Visible;
                this.Activate();
            }
        }

        private string? DecodeQrFromBitmap(System.Drawing.Bitmap bitmap)
        {
            try
            {
                var width = bitmap.Width;
                var height = bitmap.Height;
                var rect = new System.Drawing.Rectangle(0, 0, width, height);
                var bmpData = bitmap.LockBits(rect, System.Drawing.Imaging.ImageLockMode.ReadOnly, bitmap.PixelFormat);
                try
                {
                    int bytesCount = Math.Abs(bmpData.Stride) * bitmap.Height;
                    byte[] rgbValues = new byte[bytesCount];
                    System.Runtime.InteropServices.Marshal.Copy(bmpData.Scan0, rgbValues, 0, bytesCount);

                    ZXing.RGBLuminanceSource.BitmapFormat format = ZXing.RGBLuminanceSource.BitmapFormat.BGRA32;
                    if (bitmap.PixelFormat == System.Drawing.Imaging.PixelFormat.Format24bppRgb)
                    {
                        format = ZXing.RGBLuminanceSource.BitmapFormat.BGR24;
                    }

                    var luminanceSource = new ZXing.RGBLuminanceSource(rgbValues, width, height, format);
                    var binarizer = new ZXing.Common.HybridBinarizer(luminanceSource);
                    var binaryBitmap = new ZXing.BinaryBitmap(binarizer);
                    
                    var reader = new ZXing.MultiFormatReader();
                    var hints = new Dictionary<ZXing.DecodeHintType, object>
                    {
                        { ZXing.DecodeHintType.POSSIBLE_FORMATS, new List<ZXing.BarcodeFormat> { ZXing.BarcodeFormat.QR_CODE } },
                        { ZXing.DecodeHintType.TRY_HARDER, true }
                    };
                    
                    var result = reader.decode(binaryBitmap, hints);
                    return result?.Text;
                }
                finally
                {
                    bitmap.UnlockBits(bmpData);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("QR decode error: " + ex.Message);
                return null;
            }
        }

        private void ParseAndFillOtpAuth(string text)
        {
            text = text.Trim();
            if (text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var uri = new Uri(text);
                    string path = Uri.UnescapeDataString(uri.AbsolutePath).TrimStart('/');
                    string name = "";
                    string email = "";
                    string secret = "";

                    int colonIndex = path.IndexOf(':');
                    if (colonIndex >= 0)
                    {
                        name = path.Substring(0, colonIndex).Trim();
                        email = path.Substring(colonIndex + 1).Trim();
                    }
                    else
                    {
                        name = path;
                    }

                    string query = uri.Query;
                    var queryParams = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    if (!string.IsNullOrEmpty(query))
                    {
                        var pairs = query.TrimStart('?').Split('&');
                        foreach (var pair in pairs)
                        {
                            var parts = pair.Split('=');
                            if (parts.Length == 2)
                            {
                                queryParams[Uri.UnescapeDataString(parts[0])] = Uri.UnescapeDataString(parts[1]);
                            }
                        }
                    }

                    if (queryParams.TryGetValue("secret", out var sec))
                    {
                        secret = sec;
                    }
                    if (queryParams.TryGetValue("issuer", out var iss) && !string.IsNullOrEmpty(iss))
                    {
                        name = iss;
                    }

                    if (!string.IsNullOrEmpty(secret))
                    {
                        ModalAccName.Text = name;
                        ModalAccEmail.Text = email;
                        ModalAccSecret.Text = secret;
                        ShowToast("קוד ה-QR נקרא והשדות מולאו בהצלחה! ✨", false);
                    }
                    else
                    {
                        ShowToast("קוד ה-QR פוענח אך לא נמצא מפתח סודי.", true);
                    }
                }
                catch (Exception ex)
                {
                    ShowToast($"שגיאה בפענוח קישור ה-OTP: {ex.Message}", true);
                }
            }
            else
            {
                string cleaned = text.Replace(" ", "").Replace("-", "").ToUpper();
                bool isBase32 = true;
                foreach (char c in cleaned)
                {
                    if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')))
                    {
                        isBase32 = false;
                        break;
                    }
                }

                if (isBase32 && cleaned.Length >= 8)
                {
                    ModalAccSecret.Text = cleaned;
                    ShowToast("מפתח סודי נקרא בהצלחה מהקוד! 🔑", false);
                }
            }
        }



        private static string HashPassword(string password)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(bytes);
            }
        }


        public class GetVaultResult
        {
            public bool success { get; set; }
            public bool registered { get; set; }
            public string vault { get; set; } = "";
            public string message { get; set; } = "";
            public string updatedAt { get; set; } = "";
        }
    }



    // ----------------------------------------------------
    // ViewModel for binding GoogleAccount data to card UI
    // ----------------------------------------------------
    public class AccountViewModel : INotifyPropertyChanged
    {
        private string _code = "000 000";
        private double _strokeDashOffset = 0;
        private string _timerText = "30";
        private Brush _timerBrush = Brushes.Green;
        private bool _isExpanded = false;

        public GoogleAccount Account { get; }

        public AccountViewModel(GoogleAccount account)
        {
            Account = account;
        }

        public string id => Account.id;
        public string name => Account.name;
        public string email => Account.email;
        public string notes => Account.notes;
        public List<BackupCode> backupCodes => Account.backupCodes;

        public string Code
        {
            get => _code;
            set { _code = value; OnPropertyChanged(nameof(Code)); }
        }

        public double StrokeDashOffset
        {
            get => _strokeDashOffset;
            set { _strokeDashOffset = value; OnPropertyChanged(nameof(StrokeDashOffset)); }
        }

        public string TimerText
        {
            get => _timerText;
            set { _timerText = value; OnPropertyChanged(nameof(TimerText)); }
        }

        public Brush TimerBrush
        {
            get => _timerBrush;
            set { _timerBrush = value; OnPropertyChanged(nameof(TimerBrush)); }
        }

        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                _isExpanded = value;
                OnPropertyChanged(nameof(IsExpanded));
                OnPropertyChanged(nameof(DetailsVisibility));
            }
        }

        public Visibility DetailsVisibility => IsExpanded ? Visibility.Visible : Visibility.Collapsed;

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged(string name)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}