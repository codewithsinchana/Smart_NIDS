import java.io.*;
import java.util.*;

// Class to store one expense record
class Expense implements Serializable {
    String category;
    double amount;
    String date;
    String description;

    Expense(String category, double amount, String date, String description) {
        this.category = category;
        this.amount = amount;
        this.date = date;
        this.description = description;
    }

    public String toString() {
        return String.format("%-10s | ₹%-8.2f | %-10s | %s", category, amount, date, description);
    }
}

public class Smartracker {
    static final String FILE_NAME = "Smartracker.dat";
    static List<Expense> expenses = new ArrayList<>();

    public static void main(String[] args) {
        loadExpenses(); // Load old data if available
        Scanner sc = new Scanner(System.in);
        int choice;

        System.out.println(" Welcome to Smart Expense Tracker ");

        do {
            System.out.println("\n 1 Add Expense");
            System.out.println("2 View All Expenses");
            System.out.println("3 View Total by Category");
            System.out.println("4 Save & Exit");
            System.out.print(" Enter choice: ");
            choice = sc.nextInt();
            sc.nextLine(); 

            switch (choice) {
                case 1 -> addExpense(sc);
                case 2 -> viewExpenses();
                case 3 -> viewByCategory();
                case 4 -> {
                    saveExpenses();
                    System.out.println("Data saved to " + FILE_NAME + ". Goodbye!");
                }
                default -> System.out.println(" Invalid choice! Try again.");
            }
        } while (choice != 4);

        sc.close();
    }

    //Add a new expense
    static void addExpense(Scanner sc) {
        System.out.print("Enter category (Food/Travel/Shopping/Others): ");
        String category = sc.nextLine();

        System.out.print("Enter amount: ₹");
        double amount = sc.nextDouble();
        sc.nextLine();

        System.out.print("Enter date (DD-MM-YYYY): ");
        String date = sc.nextLine();

        System.out.print("Enter short description: ");
        String desc = sc.nextLine();

        expenses.add(new Expense(category, amount, date, desc));
        System.out.println("Expense added successfully!");
    }

    //View all expenses
    static void viewExpenses() {
        if (expenses.isEmpty()) {
            System.out.println("No expenses found!");
            return;
        }
        System.out.println("\n----- All Expenses -----");
        for (Expense e : expenses)
            System.out.println(e);
    }

    //View total by category
    static void viewByCategory() {
        if (expenses.isEmpty()) {
            System.out.println("No data to show!");
            return;
        }

        Map<String, Double> total = new HashMap<>();
        for (Expense e : expenses) {
            total.put(e.category, total.getOrDefault(e.category, 0.0) + e.amount);
        }

        System.out.println("\n----- Total by Category -----");
        for (var entry : total.entrySet()) {
            System.out.println(entry.getKey() + ": ₹" + entry.getValue());
        }
    }

    //Save expenses to file
    static void saveExpenses() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE_NAME))) {
            oos.writeObject(expenses);
        } catch (Exception e) {
            System.out.println("Error saving data: " + e);
        }
    }

    //Load saved expenses
    @SuppressWarnings("unchecked")
    static void loadExpenses() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(FILE_NAME))) {
            expenses = (List<Expense>) ois.readObject();
        } catch (Exception e) {
            // Ignore if file doesn't exist yet
        }
    }
}
