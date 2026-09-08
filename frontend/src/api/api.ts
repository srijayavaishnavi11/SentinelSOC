const API_URL=import.meta.env.VITE_API_URL;
export async function getDashboardStats(){
    const response = await fetch(
        `${API_URL}/dashboard/stats`
    );
    if(!response.ok){
        throw new Error("Failed to fetch dashboard stats");
    }
    return response.json();
}
export async function getAlerts(){
    const response = await fetch(
        `${API_URL}/alerts`
    );
    if(!response.ok){
        throw new Error("Failed to fetch alerts");
    }
    return response.json();
}