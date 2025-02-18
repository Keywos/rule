let x = JSON.parse($response.body);
if (x?.data) x.data={};
$done({ body: JSON.stringify(x)});