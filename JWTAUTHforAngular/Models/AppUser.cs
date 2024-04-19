using Microsoft.AspNetCore.Identity;

namespace JWTAUTHforAngular.Models
{
    public class AppUser : IdentityUser
    {
        public string FullName { get; set; }

    }
}
