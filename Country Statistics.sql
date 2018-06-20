select g.CountryName,
  sum(Blocks),
	sum(LoginFailures)
from ClientStatistics c, GeoIP g
where c.IPAddress = g.IPAddress
group by g.CountryName
order by 2 desc