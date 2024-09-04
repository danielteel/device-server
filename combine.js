const fs = require('fs');

const dataFiles = [];

const combinedData = [];

fs.readdirSync('.').forEach(file => {
    console.log(file);
    if (file.split('-')[0]==='data' && file.split('.')[1]==='json'){
        dataFiles.push({file});
    }
});

console.log(dataFiles);

for (const file of dataFiles){
    file.data = JSON.parse(fs.readFileSync(file.file));
}

for (const file of dataFiles){
    combinedData.push(...file.data);
}

let minTime = Number(combinedData[0].time);
combinedData.forEach(v => {
    v.time=Number(v.time);
    v.t=Number(v.t);
    v.h=Number(v.h);
    v.p=Number(v.p);
    if (v.time<minTime) minTime=v.time;
})

combinedData.forEach(v => {
    v.time=Math.round((v.time-minTime)/1000);
});

combinedData.sort( (a, b) => (a.time-b.time) );

fs.writeFileSync('./combined.json', JSON.stringify(combinedData));

