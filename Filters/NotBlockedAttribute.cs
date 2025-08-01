using backend.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Linq;
using System.Security.Claims;

namespace backend.Filters
{
  public class NotBlockedAttribute : Attribute, IAuthorizationFilter
  {
    public void OnAuthorization(AuthorizationFilterContext context)
    {
      var userIdClaim = context.HttpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier || c.Type == "sub");
      if (userIdClaim == null)
      {
        context.Result = new UnauthorizedResult();
        return;
      }

      var dbContext = context.HttpContext.RequestServices.GetService(typeof(ApplicationDbContext)) as ApplicationDbContext;
      if (dbContext == null)
      {
        context.Result = new StatusCodeResult(500);
        return;
      }

      if (!Guid.TryParse(userIdClaim.Value, out var userId))
      {
        context.Result = new UnauthorizedResult();
        return;
      }

      var user = dbContext.Users.FirstOrDefault(u => u.Id == userId);
      if (user == null || user.IsBlocked || user.IsDeleted)
      {
        context.Result = new ForbidResult();
        return;
      }
    }
  }
}
