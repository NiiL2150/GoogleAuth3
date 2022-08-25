using System.ComponentModel;

namespace GoogleAuth3.Models
{
    public class UserViewModel
    {
        [DisplayName("Username: ")]
        public string Username { get; set; }

        [DisplayName("Email: ")]
        public string Email { get; set; }

        [DisplayName("Role: ")]
        public string Role { get; set; }
    }
}
