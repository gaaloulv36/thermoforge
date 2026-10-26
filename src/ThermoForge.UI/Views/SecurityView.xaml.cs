using System.Windows;
using System.Windows.Controls;
using ThermoForge.UI.ViewModels;

namespace ThermoForge.UI.Views;

public partial class SecurityView : UserControl
{
    public SecurityView()
    {
        InitializeComponent();
    }

    /// <summary>PasswordBox can't be bound (by design), so the key is handed over here and cleared at once.</summary>
    private void OnSaveKey(object sender, RoutedEventArgs e)
    {
        ((SecurityViewModel)DataContext).SaveKeyCommand.Execute(KeyBox.Password);
        KeyBox.Clear();
    }
}
