using System.ComponentModel.DataAnnotations;

namespace AuthBasic.Models;

public class RegisterModel
{
    [Required(ErrorMessage = "User Name is required")]
    public string? Username { get; set; }

    [Required(ErrorMessage = "User first name is required")]
    public string FirstName { get; set; }

    [Required(ErrorMessage = "User last name is required")]
    public string LastName { get; set; }

    [EmailAddress]
    [Required(ErrorMessage = "Email is required")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    public string? Password { get; set; }
}