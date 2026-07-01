using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using Tether.DesktopUI.Services;

namespace Tether.DesktopUI.ViewModels;

public class MainViewModel : INotifyPropertyChanged
{
    private readonly PipeClientService _pipeService;
    private object _currentPage = null!;
    private NavItem _selectedNavItem = null!;

    public ObservableCollection<NavItem> NavItems { get; } = new();

    public object CurrentPage
    {
        get => _currentPage;
        set { _currentPage = value; OnPropertyChanged(); }
    }

    public NavItem SelectedNavItem
    {
        get => _selectedNavItem;
        set { _selectedNavItem = value; OnPropertyChanged(); NavigateTo(value); }
    }

    public MainViewModel(PipeClientService pipeService, ConfigViewModel configVM, StatusViewModel statusVM, LogsViewModel logsVM)
    {
        _pipeService = pipeService;
        NavItems.Add(new NavItem { Name = "Configuration", Icon = "Cog", ViewModel = configVM });
        NavItems.Add(new NavItem { Name = "Status", Icon = "MonitorDashboard", ViewModel = statusVM });
        NavItems.Add(new NavItem { Name = "Logs", Icon = "FileDocument", ViewModel = logsVM });

        SelectedNavItem = NavItems[0];
        _pipeService.Start();
    }

    private void NavigateTo(NavItem item)
    {
        if (item?.ViewModel != null)
            CurrentPage = item.ViewModel;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string name = null!) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class NavItem
{
    public string Name { get; set; } = string.Empty;
    public string Icon { get; set; } = string.Empty;
    public object ViewModel { get; set; } = null!;
}