select cs.IPAddress,
  cs.LastFailedLogin,
	cs.UnblockDate,
	cs.FailedLogins,
	cs.Blocked,
	cs.FirewallRule,
	g.Host,
	g.ISP,
	g.City,
	g.CountryName,
	g.Latitude,
	g.Longitude
from ClientStatus cs
left join GeoIP g
  on g.IPAddress = cs.IPAddress
order by cs.LastFailedLogin desc