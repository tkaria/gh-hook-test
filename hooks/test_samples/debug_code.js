// Sample file with debug statements for testing the review agent

function processData(data) {
    console.log("DEBUG: processing data", data);
    debugger;

    // TODO: implement proper validation
    // FIXME: this is a temporary workaround

    const apiUrl = "http://localhost:3000/api/data";

    return fetch(apiUrl).then(res => res.json());
}
