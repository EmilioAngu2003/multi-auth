using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace multi_auth.Pages;

[Authorize]
public class ProfileModel : PageModel
{
    public void OnGet()
    {
    }
}
