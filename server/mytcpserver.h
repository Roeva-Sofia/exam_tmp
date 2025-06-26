#ifndef MYTCPSERVER_H
#define MYTCPSERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QList>
#include <QMap>
#include <QVector>

class TcpServer : public QObject
{
    Q_OBJECT

public:
    explicit TcpServer(QObject* parent = nullptr);
    ~TcpServer();

private slots:
    void handleNewConnection();
    void handleClientDisconnected(QTcpSocket* socket);

private:
    void processClientData(QTcpSocket* socket, const QString& rawCommand);
    void processRegistration(QTcpSocket* socket, const QString& credentials);
    void processAuthentication(QTcpSocket* socket, const QString& credentials);
    void sendResponse(QTcpSocket* socket, const QString& message);
    void broadcast(const QString& message);
    void startQuiz();
    void askQuestion();
    void processAnswer(QTcpSocket* socket, const QString& answer);
    void endQuiz();
    bool allClientsAuthenticated() const;

    QTcpServer* m_server;
    QList<QTcpSocket*> m_connectedClients;
    QMap<QTcpSocket*, QString> m_clientNames;
    QMap<QTcpSocket*, int> m_scores;

    static const int MAX_CLIENTS = 3;
    bool m_quizActive;
    int m_currentQuestion;
    QVector<QPair<QString, QString>> m_questions;
};

#endif // MYTCPSERVER_H
