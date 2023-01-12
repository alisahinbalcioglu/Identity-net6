using Authenticate.Contexts;
using Authenticate.Models;
using Microsoft.EntityFrameworkCore;

namespace Authenticate.Services
{
    public class TenantService : ITenantService
    {
        private ApplicationDBContext db;
        private DbSet<Tenant> tenants;

#pragma warning disable CS8618 // Null atanamaz alan, oluşturucudan çıkış yaparken null olmayan bir değer içermelidir. Alanı null atanabilir olarak bildirmeyi düşünün.
        public TenantService(ApplicationDBContext db)
#pragma warning restore CS8618 // Null atanamaz alan, oluşturucudan çıkış yaparken null olmayan bir değer içermelidir. Alanı null atanabilir olarak bildirmeyi düşünün.
        {
            this.db = db;
#pragma warning disable CS8601 // Olası null başvuru ataması.
            this.tenants = db.Tenants;
#pragma warning restore CS8601 // Olası null başvuru ataması.
        }

        public async Task<ResponseModel> AddNewTenantAsync(RegisterTenantModel tenant)
        {
            var newTenant = tenants.Add(new Tenant { TenantId = tenant.TenantId });
            await db.SaveChangesAsync();
            return new ResponseModel() { Object = newTenant.Entity, Message = "new Tenant Added", Status = "Success", StatusCode = StatusCodes.Status200OK };
        }
    }
}
