using System.Windows;
using Tether.DesktopUI.ViewModels;

namespace Tether.DesktopUI.Views;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}