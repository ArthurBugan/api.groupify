use anyhow::{Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Row};
use tokio::sync::RwLock;

/// Represents a book, taken from the books table in Postgres.
#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
pub struct Book {
    /// The book's primary key ID
    pub id: i32,
    /// The book's title
    pub title: String,
    /// The book's author (surname, lastname - not enforced)
    pub author: String,
}

struct BookCache {
    all_books: RwLock<Option<Vec<Book>>>,
}

impl BookCache {
    fn new() -> Self {
        Self {
            all_books: RwLock::new(None),
        }
    }

    async fn all_books(&self) -> Option<Vec<Book>> {
        let lock = self.all_books.read().await;
        lock.clone()
    }

    async fn refresh(&self, books: Vec<Book>) {
        let mut lock = self.all_books.write().await;
        *lock = Some(books);
    }

    async fn invalidate(&self) {
        let mut lock = self.all_books.write().await;
        *lock = None;
    }
}

static CACHE: Lazy<BookCache> = Lazy::new(BookCache::new);

/// Create a database connection pool. Run any migrations.
///
/// ## Returns
/// * A ready-to-use connection pool.
pub async fn init_db() -> Result<PgPool> {
    let database_url = std::env::var("DATABASE_URL")?;

    let connection_pool = PgPool::connect(&database_url).await?;
    sqlx::migrate!().run(&connection_pool).await?;
    Ok(connection_pool)
}

/// Retrieves all books, sorted by title and then author.
///
/// ## Arguments
/// * `connection_pool` - the connection pool to use.
///
/// ## Returns
/// * A vector of books, or an error.
pub async fn all_books(connection_pool: &PgPool) -> Result<Vec<Book>> {
    if let Some(all_books) = CACHE.all_books().await {
        Ok(all_books)
    } else {
        let books = sqlx::query_as::<_, Book>("SELECT * FROM books ORDER BY title,author")
            .fetch_all(connection_pool)
            .await?;
        CACHE.refresh(books.clone()).await;
        Ok(books)
    }
}

/// Retrieves a single book, by ID
///
/// ## Arguments
/// * `connection_pool` - the database connection pool to use
/// * `id` - the primary key of the book to retrieve
pub async fn book_by_id(connection_pool: &PgPool, id: i32) -> Result<Book> {
    Ok(sqlx::query_as::<_, Book>("SELECT * FROM books WHERE id=$1")
        .bind(id)
        .fetch_one(connection_pool)
        .await?)
}

/// Adds a book to the database.
///
/// ## Arguments
/// * `connection_pool` - the database connection to use
/// * `title` - the title of the book to add
/// * `author` - the author of the book to add
///
/// ## Returns
/// * The primary key value of the new book
pub async fn add_book<S: ToString>(connection_pool: &PgPool, title: S, author: S) -> Result<i32> {
    let title = title.to_string();
    let author = author.to_string();
    let id = sqlx::query("INSERT INTO books (title, author) VALUES ($1, $2) RETURNING id")
        .bind(title)
        .bind(author)
        .fetch_one(connection_pool)
        .await?
        .get(0);
    CACHE.invalidate().await;
    Ok(id)
}

/// Update a book
///
/// ## Arguments
/// * `connection_pool` - the database connection to use
/// * `book` - the book object to update. The primary key will be used to
///            determine which row is updated.
pub async fn update_book(connection_pool: &PgPool, book: &Book) -> Result<()> {
    sqlx::query("UPDATE books SET title=$1, author=$2 WHERE id=$3")
        .bind(&book.title)
        .bind(&book.author)
        .bind(&book.id)
        .execute(connection_pool)
        .await?;
    CACHE.invalidate().await;
    Ok(())
}

/// Delete a book
///
/// ## Arguments
/// * `connection_pool` - the database connection to use
/// * `id` - the primary key of the book to delete
pub async fn delete_book(connection_pool: &PgPool, id: i32) -> Result<()> {
    sqlx::query("DELETE FROM books WHERE id=$1")
        .bind(id)
        .execute(connection_pool)
        .await?;
    CACHE.invalidate().await;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    /*
    #[sqlx::test]
    async fn get_all() {
        dotenv::dotenv().ok();
        let cnn = init_db().await.unwrap();
        let all_rows = all_channels(&cnn).await.unwrap();
        assert!(!all_rows.is_empty());
    }

    #[sqlx::test]
    async fn get_one() {
        dotenv::dotenv().ok();
        let cnn = init_db().await.unwrap();
        let book = book_by_id(&cnn, 1).await.unwrap();
        assert_eq!(1, book.id);
        assert_eq!("Hands-on Rust", book.title);
        assert_eq!("Wolverson, Herbert", book.author);
    }

    #[sqlx::test]
    async fn test_create() {
        dotenv::dotenv().ok();
        let cnn = init_db().await.unwrap();
        let new_id = add_book(&cnn, "Test Book", "Test Author").await.unwrap();
        let new_book = book_by_id(&cnn, new_id).await.unwrap();
        assert_eq!(new_id, new_book.id);
        assert_eq!("Test Book", new_book.title);
        assert_eq!("Test Author", new_book.author);
    }

    #[sqlx::test]
    async fn test_update() {
        dotenv::dotenv().ok();
        let cnn = init_db().await.unwrap();
        let mut book = book_by_id(&cnn, 2).await.unwrap();
        book.title = "Updated Book".to_string();
        update_book(&cnn, &book).await.unwrap();
        let updated_book = book_by_id(&cnn, 2).await.unwrap();
        assert_eq!("Updated Book", updated_book.title);
    }

    #[sqlx::test]
    async fn test_delete() {
        dotenv::dotenv().ok();
        let cnn = init_db().await.unwrap();
        let new_id = add_book(&cnn, "DeleteMe", "Test Author").await.unwrap();
        let _new_book = book_by_id(&cnn, new_id).await.unwrap();
        delete_book(&cnn, new_id).await.unwrap();
        let all_books = all_books(&cnn).await.unwrap();
        assert!(all_books.iter().find(|b| b.title == "DeleteMe").is_none());
    }
     */
}
